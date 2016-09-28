// +build linux

package loop_overlay2

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"

	"github.com/docker/docker/daemon/graphdriver"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/directory"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/loopback"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/docker/pkg/parsers"
	"github.com/docker/docker/pkg/parsers/kernel"

	"github.com/opencontainers/runc/libcontainer/label"
)

var (
	// untar defines the untar method
	untar = chrootarchive.UntarUncompressed
)

// This backend uses the overlay union filesystem for containers
// with diff directories for each layer.

// This version of the overlay driver requires at least kernel
// 4.0.0 in order to support mounting multiple diff directories.

// Each container/image has at least a "diff" directory and "link" file.
// If there is also a "lower" file when there are diff layers
// below  as well as "merged" and "work" directories. The "diff" directory
// has the upper layer of the overlay and is used to capture any
// changes to the layer. The "lower" file contains all the lower layer
// mounts separated by ":" and ordered from uppermost to lowermost
// layers. The overlay itself is mounted in the "merged" directory,
// and the "work" dir is needed for overlay to work.

// The "link" file for each layer contains a unique string for the layer.
// Under the "l" directory at the root there will be a symbolic link
// with that unique string pointing the "diff" directory for the layer.
// The symbolic links are used to reference lower layers in the "lower"
// file and on mount. The links are used to shorten the total length
// of a layer reference without requiring changes to the layer identifier
// or root directory. Mounts are always done relative to root and
// referencing the symbolic links in order to ensure the number of
// lower directories can fit in a single page for making the mount
// syscall. A hard upper limit of 128 lower layers is enforced to ensure
// that mounts do not fail due to length.

const (
	driverName = "loop_overlay2"
	linkDir    = "l"
	lowerFile  = "lower"
	maxDepth   = 128

	// idLength represents the number of random characters
	// which can be used to create the unique link identifer
	// for every layer. If this value is too long then the
	// page size limit for the mount command may be exceeded.
	// The idLength should be selected such that following equation
	// is true (512 is a buffer for label metadata).
	// ((idLength + len(linkDir) + 1) * maxDepth) <= (pageSize - 512)
	idLength = 26
)

// Driver contains information about the home directory and the list of active mounts that are created using this driver.
type Driver struct {
	home    string
	loopbackDir	string
	filesystem string
	mkfsArgs []string
	uidMaps []idtools.IDMap
	gidMaps []idtools.IDMap
	ctr     *graphdriver.RefCounter
}

var backingFs = "<unknown>"
var loopbackRoot = "/var/lib/docker/loopback/root"
var loopbackFallback = "/var/lib/docker/loopback/private"

func init() {
	graphdriver.Register(driverName, Init)
}

// Init returns the a native diff driver for overlay filesystem.
// If overlay filesystem is not supported on the host, graphdriver.ErrNotSupported is returned as error.
// If an overlay filesystem is not supported over an existing filesystem then error graphdriver.ErrIncompatibleFS is returned.
func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {
	opts, err := parseOptions(options)
	if err != nil {
		return nil, err
	}

	if err := supportsOverlay(); err != nil {
		return nil, graphdriver.ErrNotSupported
	}

	// require kernel 4.0.0 to ensure multiple lower dirs are supported
	v, err := kernel.GetKernelVersion()
	if err != nil {
		return nil, err
	}
	if kernel.CompareKernelVersion(*v, kernel.VersionInfo{Kernel: 4, Major: 0, Minor: 0}) < 0 {
		if !opts.overrideKernelCheck {
			return nil, graphdriver.ErrNotSupported
		}
		logrus.Warnf("Using pre-4.0.0 kernel for overlay2, mount failures may require kernel update")
	}

	fsMagic, err := graphdriver.GetFSMagic(home)
	if err != nil {
		return nil, err
	}
	if fsName, ok := graphdriver.FsNames[fsMagic]; ok {
		backingFs = fsName
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	// Create the driver home dir
	if err := idtools.MkdirAllAs(path.Join(home, linkDir), 0700, rootUID, rootGID); err != nil && !os.IsExist(err) {
		return nil, err
	}

	if err := mount.MakePrivate(home); err != nil {
		return nil, err
	}

	// Create the loopback dir
	loopbackDir := path.Join(loopbackRoot, "devs")

	if err := idtools.MkdirAllAs(loopbackDir, 0700, rootUID, rootGID); err != nil && !os.IsExist(err) {
		return nil, err
	}

	if err := mount.MakePrivate(loopbackDir); err != nil {
		return nil, err
	}

	filesystem := determineDefaultFS()

	d := &Driver{
		home:    home,
		loopbackDir: loopbackDir,
		filesystem: filesystem,
		uidMaps: uidMaps,
		gidMaps: gidMaps,
		ctr:     graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicOverlay)),
	}

	return d, nil
}

type overlayOptions struct {
	overrideKernelCheck bool
}

func parseOptions(options []string) (*overlayOptions, error) {
	o := &overlayOptions{}
	for _, option := range options {
		key, val, err := parsers.ParseKeyValueOpt(option)
		if err != nil {
			return nil, err
		}
		key = strings.ToLower(key)
		switch key {
		case "loop_overlay2.override_kernel_check":
			o.overrideKernelCheck, err = strconv.ParseBool(val)
			if err != nil {
				return nil, err
			}
		case "loop_overlay2.loopback_root":
			loopbackRoot = val
		case "loop_overlay2.loopback_fallback":
			loopbackFallback = val
		default:
			return nil, fmt.Errorf("loop_overlay2: Unknown option %s\n", key)
		}
	}
	return o, nil
}

func supportsOverlay() error {
	// We can try to modprobe overlay first before looking at
	// proc/filesystems for when overlay is supported
	exec.Command("modprobe", "overlay").Run()

	f, err := os.Open("/proc/filesystems")
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if s.Text() == "nodev\toverlay" {
			return nil
		}
	}
	logrus.Error("'overlay' not found as a supported filesystem on this host. Please ensure kernel is new enough and has overlay support loaded.")
	return graphdriver.ErrNotSupported
}

func (d *Driver) String() string {
	return driverName
}

// Status returns current driver information in a two dimensional string array.
// Output contains "Backing Filesystem" used in this implementation.
func (d *Driver) Status() [][2]string {
	return [][2]string{
		{"Backing Filesystem", backingFs},
		{"Loopback Root", loopbackRoot},
		{"Loopback Fallback Directory", loopbackFallback},
	}
}

// GetMetadata returns meta data about the overlay driver such as
// LowerDir, UpperDir, WorkDir and MergeDir used to store data.
func (d *Driver) GetMetadata(id string) (map[string]string, error) {
	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"WorkDir":   path.Join(dir, "work"),
		"MergedDir": path.Join(dir, "merged"),
		"UpperDir":  path.Join(dir, "diff"),
	}

	lowerDirs, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}
	if len(lowerDirs) > 0 {
		metadata["LowerDir"] = strings.Join(lowerDirs, ":")
	}

	return metadata, nil
}

// Cleanup any state created by overlay which should be cleaned when daemon
// is being shutdown. For now, we just have to unmount the bind mounted
// we had created.
func (d *Driver) Cleanup() error {
	return mount.Unmount(d.home)
}

// CreateReadWrite creates a layer that is writable for use as a container
// file system.
func (d *Driver) CreateReadWrite(id, parent, mountLabel string, storageOpt map[string]string) error {
	return d.Create(id, parent, mountLabel, storageOpt)
}

// Create is used to create the upper, lower, and merge directories required for overlay fs for a given id.
// The parent filesystem is used to configure these directories for the overlay.
func (d *Driver) Create(id, parent, mountLabel string, storageOpt map[string]string) (retErr error) {

	if len(storageOpt) != 0 {
		return fmt.Errorf("--storage-opt is not supported for overlay")
	}

	dir := d.dir(id)

	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return err
	}
	if err := idtools.MkdirAllAs(path.Dir(dir), 0700, rootUID, rootGID); err != nil {
		return err
	}
	if err := idtools.MkdirAs(dir, 0700, rootUID, rootGID); err != nil {
		return err
	}

	defer func() {
		// Clean up on failure
		if retErr != nil {
			os.RemoveAll(dir)
		}
	}()

	if err := idtools.MkdirAs(path.Join(dir, "diff"), 0755, rootUID, rootGID); err != nil {
		return err
	}

	lid := generateID(idLength)
	if err := os.Symlink(path.Join("..", id, "diff"), path.Join(d.home, linkDir, lid)); err != nil {
		return err
	}

	// Write link id to link file
	if err := ioutil.WriteFile(path.Join(dir, "link"), []byte(lid), 0644); err != nil {
		return err
	}

	// if no parent directory, done
	if parent == "" {
		return nil
	}

	if err := idtools.MkdirAs(path.Join(dir, "work"), 0700, rootUID, rootGID); err != nil {
		return err
	}
	if err := idtools.MkdirAs(path.Join(dir, "merged"), 0700, rootUID, rootGID); err != nil {
		return err
	}

	lower, err := d.getLower(parent)
	if err != nil {
		return err
	}
	if lower != "" {
		if err := ioutil.WriteFile(path.Join(dir, lowerFile), []byte(lower), 0666); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) getLower(parent string) (string, error) {
	parentDir := d.dir(parent)

	// Ensure parent exists
	if _, err := os.Lstat(parentDir); err != nil {
		return "", err
	}

	// Read Parent link fileA
	parentLink, err := ioutil.ReadFile(path.Join(parentDir, "link"))
	if err != nil {
		return "", err
	}
	lowers := []string{path.Join(linkDir, string(parentLink))}

	parentLower, err := ioutil.ReadFile(path.Join(parentDir, lowerFile))
	if err == nil {
		parentLowers := strings.Split(string(parentLower), ":")
		lowers = append(lowers, parentLowers...)
	}
	if len(lowers) > maxDepth {
		return "", errors.New("max depth exceeded")
	}
	return strings.Join(lowers, ":"), nil
}

func (d *Driver) dir(id string) string {
	return path.Join(d.home, id)
}

func (d *Driver) getLowerDirs(id string) ([]string, error) {
	var lowersArray []string
	lowers, err := ioutil.ReadFile(path.Join(d.dir(id), lowerFile))
	if err == nil {
		for _, s := range strings.Split(string(lowers), ":") {
			lp, err := os.Readlink(path.Join(d.home, s))
			if err != nil {
				return nil, err
			}
			lowersArray = append(lowersArray, path.Clean(path.Join(d.home, "link", lp)))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return lowersArray, nil
}

// Remove cleans the directories that are created for this id.
func (d *Driver) Remove(id string) error {
	dir := d.dir(id)
	lid, err := ioutil.ReadFile(path.Join(dir, "link"))
	if err == nil {
		if err := os.RemoveAll(path.Join(d.home, linkDir, string(lid))); err != nil {
			logrus.Debugf("Failed to remove link: %v", err)
		}
	}

	logrus.Debugf("Removing dir %s", dir)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (d *Driver) getIdFromLink(linkPath string) (string, error) {
	path, err := os.Readlink(linkPath)
	if err != nil {
		return "", err
	}

	suffix := "/diff"

	//  Check that we received a correctly formatted path
	if ! strings.HasSuffix(path, suffix) {
		return "", fmt.Errorf("loop_overlay2: path does not contain diff directory: %s\n", path)
	}

	// Get the dir without "/diff"
	absIdPath := strings.TrimSuffix(path, suffix)
	id := filepath.Base(absIdPath)
	if (id == ".") || (id == "/") {
		return "", fmt.Errorf("loop_overlay2: path not in expected format: %s\n", path)
	}

	return id, nil
}


func (d *Driver) mountLowerIds(ids []string) (error) {
	if ids == nil {
		return fmt.Errorf("loop_overlay2: no IDs of lower layers to mount")
	}


	var mounts []string
	var loops []*os.File
	var savedError error

	failure := false

	// Iterate through the array of lower ids to mount. Failures are acceptable
	// if the loopback file does not exist. In that case the layer is the top
	// ephemeral layer that belongs to the container. As such, it will not be
	// found on shared storage
	for _, id := range ids {
		loopFile := path.Join(d.loopbackDir, id)
		_, err := os.Stat(loopFile)
		if err == nil {

			// The loopback file is present on shared storage, so
			// mount it
			loopDev, err := loopback.AttachLoopDevice(loopFile)
			if err != nil {
				savedError = err
				failure = true
				return err
			}
			logrus.Debugf("loop_overlay2: attached loop dev %s to image %s", loopDev.Name(), loopFile)
			//loops = append(loops, loopDev)

			applyDir := d.getDiffPath(id)

			// Mount the device
			mountRW := false
			err = d.MountLoopbackDevice(loopDev.Name(), applyDir, id, mountRW)
			if err != nil {
				savedError = err
				failure = true
				defer loopDev.Close()
				break
			}
			mounts = append(mounts, applyDir)
		}

	}

	// Cleanup mounts if there was a failure
	if failure {
		for i, m := range mounts {
			err := syscall.Unmount(m, syscall.MNT_DETACH)
			if err != nil {
				logrus.Errorf("loop_overlay2: failed to unmount %s", m)
			}

			// detach the loop device
			defer loops[i].Close()
		}

		return savedError
	}

	return nil
}

func (d *Driver) getDiffPath(id string) string {
	dir := d.dir(id)

	return path.Join(dir, "diff")
}

// Get creates and mounts the required file system for the given id and returns the mount path.
func (d *Driver) Get(id string, mountLabel string) (s string, err error) {
	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}

	diffDir := path.Join(dir, "diff")

	lowers, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If no lower, just return diff directory
		if os.IsNotExist(err) {
			return diffDir, nil
		}
		return "", err
	}

	mergedDir := path.Join(dir, "merged")
	if count := d.ctr.Increment(mergedDir); count > 1 {
		return mergedDir, nil
	}
	defer func() {
		if err != nil {
			if c := d.ctr.Decrement(mergedDir); c <= 0 {
				syscall.Unmount(mergedDir, 0)
			}
		}
	}()

	workDir := path.Join(dir, "work")
	splitLowers := strings.Split(string(lowers), ":")
	absLowers := make([]string, len(splitLowers))

	lowerIds := make([]string, len(splitLowers))

	for i, s := range splitLowers {
		absLowers[i] = path.Join(d.home, s)
		lowerIds[i], err = d.getIdFromLink(absLowers[i])
		if err != nil {
			lowerIds = nil
		}
	}

	err = d.mountLowerIds(lowerIds)
	if err != nil {
		return "", err
	}

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(absLowers, ":"), path.Join(dir, "diff"), path.Join(dir, "work"))
	mountData := label.FormatMountLabel(opts, mountLabel)
	mount := syscall.Mount
	mountTarget := mergedDir

	pageSize := syscall.Getpagesize()

	// Use relative paths and mountFrom when the mount data has exceeded
	// the page size. The mount syscall fails if the mount data cannot
	// fit within a page and relative links make the mount data much
	// smaller at the expense of requiring a fork exec to chroot.
	if len(mountData) > pageSize {
		opts = fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", string(lowers), path.Join(id, "diff"), path.Join(id, "work"))
		mountData = label.FormatMountLabel(opts, mountLabel)
		if len(mountData) > pageSize {
			return "", fmt.Errorf("cannot mount layer, mount label too large %d", len(mountData))
		}

		mount = func(source string, target string, mType string, flags uintptr, label string) error {
			return mountFrom(d.home, source, target, mType, flags, label)
		}
		mountTarget = path.Join(id, "merged")
	}

	if err := mount("overlay", mountTarget, "overlay", 0, mountData); err != nil {
		return "", fmt.Errorf("error creating overlay mount to %s: %v", mergedDir, err)
	}

	// chown "workdir/work" to the remapped root UID/GID. Overlay fs inside a
	// user namespace requires this to move a directory from lower to upper.
	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return "", err
	}

	if err := os.Chown(path.Join(workDir, "work"), rootUID, rootGID); err != nil {
		return "", err
	}

	return mergedDir, nil
}

func (d *Driver) unmountLowerIds(ids []string) (error) {
	if ids == nil {
		return fmt.Errorf("loop_overlay2: no IDs of lower layers to unmount")
	}

	for _, id := range ids {

		// Check if loopfile exists. If it doesn't we skip trying to unmount it
		loopFile := path.Join(d.loopbackDir, id)
		_, err := os.Stat(loopFile)
		if err == nil {
			mountPath := d.getDiffPath(id)

			if isMounted, err := mount.Mounted(mountPath); err != nil {
				return err
			} else if !isMounted {
				continue
			}

			// Unmount the loopback device
			if err := syscall.Unmount(mountPath, syscall.MNT_DETACH); err != nil {
				logrus.Errorf("loop_overlay2: failed to unmount %s", mountPath)
			}

			loopFile := path.Join(d.loopbackDir, id)
			f, err := os.Open(loopFile)
			if err != nil {
				return err
			}

			entries, err := mount.GetMounts()
			if err != nil {
				return err
			}

			// Search the table for the loop dev attached to loopFile
			for _, e := range entries {
				if e.Mountpoint == loopFile {
					// Found it. Now get the loop dev and close it.
					loopDev := loopback.GetLoopDeviceFor(f, e.Source)
					if loopDev != nil {
						defer loopDev.Close()
					}
					defer f.Close()

					// Continue to the next layer
					break
				}
			}

		}
	}

	return nil
}

// Put unmounts the mount path created for the given id.
func (d *Driver) Put(id string) error {
	dir := d.dir(id)

	mountpoint := path.Join(dir, "merged")
	if count := d.ctr.Decrement(mountpoint); count > 0 {
		return nil
	}

	if err := syscall.Unmount(mountpoint, 0); err != nil {
		logrus.Debugf("Failed to unmount %s overlay: %v", id, err)
	}

	lowers, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If there were no lower layers. the return after unmounting overlay
		return nil
	}

	splitLowers := strings.Split(string(lowers), ":")
	absLowers := make([]string, len(splitLowers))

	lowerIds := make([]string, len(splitLowers))

	for i, s := range splitLowers {
		absLowers[i] = path.Join(d.home, s)
		lowerIds[i], err = d.getIdFromLink(absLowers[i])
		if err != nil {
			lowerIds = nil
		}
	}

	err = d.unmountLowerIds(lowerIds)
	if err != nil {
		return err
	}

	return nil
}

// Exists checks to see if the id is already mounted.
func (d *Driver) Exists(id string) bool {
	logrus.Debugf("loop_overlay2: checking if layer is mounted%s", id)
	// First see if there's a directory locally in /var/lib/docker
	_, err := os.Stat(d.dir(id))
	if err == nil {
		return true
	}

	loopFile := path.Join(d.loopbackDir, id)
	_, err = os.Stat(loopFile)
	if err == nil {
		return true
	}

	return false
}

// ensureImage creates a sparse file of <size> bytes at the path
// <loopbackDir>/devs/<name>
// If the file already exists and new size is larger than its current size, it grows to the new size.
// Either way it returns the full path.
func (d *Driver) ensureImage(filename string, size int64) error {
	if fi, err := os.Stat(filename); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		logrus.Debugf("loop_overlay2: Creating loopback file %s", filename)
		file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		defer file.Close()

		if err := file.Truncate(size); err != nil {
			return err
		}
	} else {
		if fi.Size() < size {
			file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				return err
			}
			defer file.Close()
			if err := file.Truncate(size); err != nil {
				return fmt.Errorf("loop_overlay2: Unable to grow loopback file %s: %v", filename, err)
			}
		} else if fi.Size() > size {
			logrus.Warnf("loop_overlay2: Can't shrink loopback file %s", filename)
		}
	}
	return nil
}

// Return true only if kernel supports xfs and mkfs.xfs is available
func xfsSupported() bool {
	// Make sure mkfs.xfs is available
	if _, err := exec.LookPath("mkfs.xfs"); err != nil {
		return false
	}

	// Check if kernel supports xfs filesystem or not.
	exec.Command("modprobe", "xfs").Run()

	f, err := os.Open("/proc/filesystems")
	if err != nil {
		logrus.Warnf("loop_overlay2: Could not check if xfs is supported: %v", err)
		return false
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if strings.HasSuffix(s.Text(), "\txfs") {
			return true
		}
	}

	if err := s.Err(); err != nil {
		logrus.Warnf("loop_overlay2: Could not check if xfs is supported: %v", err)
	}
	return false
}

func determineDefaultFS() string {
	if xfsSupported() {
		return "xfs"
	}

	logrus.Warn("loop_overlay2: XFS is not supported in your system. Either the kernel doesn't support it or mkfs.xfs is not in your PATH. Defaulting to ext4 filesystem")
	return "ext4"
}

func (d *Driver) createFilesystem(devname string) (err error) {
	args := []string{}
	for _, arg := range d.mkfsArgs {
		args = append(args, arg)
	}

	args = append(args, devname)

	logrus.Debugf("loop_overlay2: Creating filesystem %s on device %s", d.filesystem, devname)
	defer func() {
		if err != nil {
			logrus.Infof("loop_overlay2: Error while creating filesystem %s on device %s: %v", d.filesystem, devname, err)
		} else {
			logrus.Infof("loop_overlay2: Successfully created filesystem %s on device %s", d.filesystem, devname)
		}
	}()

	switch d.filesystem {
	case "xfs":
		err = exec.Command("mkfs.xfs", args...).Run()
	case "ext4":
		err = exec.Command("mkfs.ext4", append([]string{"-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0"}, args...)...).Run()
		if err != nil {
			err = exec.Command("mkfs.ext4", append([]string{"-E", "nodiscard,lazy_itable_init=0"}, args...)...).Run()
		}
		if err != nil {
			return err
		}
		err = exec.Command("tune2fs", append([]string{"-c", "-1", "-i", "0"}, devname)...).Run()
	default:
		err = fmt.Errorf("loop_overlay2: Unsupported filesystem type %s", d.filesystem)
	}
	return
}

func (d *Driver) createLoopback(id string, size int64) (*os.File, error) {
	filename := path.Join(d.loopbackDir, id)
	createdLoopback := false

	_, err := os.Stat(filename)
	if err != nil {
		createdLoopback = true
	}

	// Create the loopback image file
	if err := d.ensureImage(filename, size); err != nil {
		logrus.Debugf("loop_overlay2: Error device ensureImage (%s): %s", id, err)
		return nil, err
	}

	loopDev, err := loopback.AttachLoopDevice(filename)
	if err != nil {
		return nil, err
	}

	// Format the device with a filesystem if it was just created
	if createdLoopback {
		if err := d.createFilesystem(loopDev.Name()); err != nil {
			logrus.Debugf("loop_overlay2: Error createFilesystem on %s: %s", loopDev.Name(), err)
			return nil, err
		}
	}

	return loopDev, nil
}

func (d *Driver) MountLoopbackDevice(dev, path, mountLabel string, mountRW bool) error {
	options := ""

	if mountRW {
		options = joinMountOptions(options, "rw")
	} else {
		options = joinMountOptions(options, "ro")
	}

	if d.filesystem == "xfs" {
		// XFS needs nouuid or it can't mount filesystems with the same fs
		options = joinMountOptions(options, "nouuid")
	}

	if err := mount.Mount(dev, path, d.filesystem, options); err != nil {
		return fmt.Errorf("loop_overlay2: Error mounting '%s' on '%s': %s", dev, path, err)
	}

	return nil
}



// ApplyDiff applies the new layer into a root
func (d *Driver) ApplyDiff(id string, parent string, diff archive.Reader) (size int64, err error) {
	tengb := func() int64 {
		return 1024 * 1024 * 1024 * 10
	}
	size = tengb()

	// Create and attach loopback device
	loopDev, err := d.createLoopback(id, size)
	if err != nil {
		return 0, err
	}

	applyDir := d.getDiffPath(id)

	// Mount the device
	mountRW := true
	if err := d.MountLoopbackDevice(loopDev.Name(), applyDir, id, mountRW); err != nil {
		return 0, err
	}

	logrus.Debugf("Applying tar in %s", applyDir)
	// Overlay doesn't need the parent id to apply the diff
	if err := untar(diff, applyDir, &archive.TarOptions{
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	}); err != nil {
		return 0, err
	}

	if err := syscall.Unmount(applyDir, syscall.MNT_DETACH); err != nil {
		return 0, err
	}

	defer loopDev.Close()
	return d.DiffSize(id, parent)
}

// DiffSize calculates the changes between the specified id
// and its parent and returns the size in bytes of the changes
// relative to its base filesystem directory.
func (d *Driver) DiffSize(id, parent string) (size int64, err error) {
	return directory.Size(d.getDiffPath(id))
}

// Diff produces an archive of the changes between the specified
// layer and its parent layer which may be "".
func (d *Driver) Diff(id, parent string) (archive.Archive, error) {
	diffPath := d.getDiffPath(id)
	logrus.Debugf("Tar with options on %s", diffPath)
	return archive.TarWithOptions(diffPath, &archive.TarOptions{
		Compression:    archive.Uncompressed,
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	})
}

// Changes produces a list of changes between the specified layer
// and its parent layer. If parent is "", then all changes will be ADD changes.
func (d *Driver) Changes(id, parent string) ([]archive.Change, error) {
	// Overlay doesn't have snapshots, so we need to get changes from all parent
	// layers.
	diffPath := d.getDiffPath(id)
	layers, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}

	return archive.OverlayChanges(layers, diffPath)
}
