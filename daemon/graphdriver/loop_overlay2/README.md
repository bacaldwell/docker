## loop_overlay2 - a shared storage backend based on loopback devices and overlay2

### Theory of operation

The loop_overlay2 graphdriver combines loopback devices (xfs or ext4)
and overlayfs to implement images composed of stacked layers with
file-based CoW. This driver should be used in favor of overlay2 when the
image store is on a shared filesystem or one that overlayfs does not support
for its lower layers.

Two options that are important to set if images will be on shared storage:
1. `--storage-opt loop_overlay2.loopback_root`
2. `--storage-opt loop_overlay2.loopback_fallback`

The first will set the preferred location for locating an existing image layer
or for creating a new one. As the name of the second option suggests, it will be
where the driver looks if there is an error using the root directory.
Handled errors are not found, permission denied, or read-only filesystem (when
pulling an image). If such and error is encountered, the driver will proceed
to attempting the operation om the fallback directory.

This driver makes use of features in kernel 4.0.0 or later that allow multiple
lower layers as part of a single overlayfs mount. If this feature is available
from the host's kernel, but the version is less than 4.0.0 (i.e. due to patches
backported by the distribution), running the Docker daemon with
`--storage-opt loop_overlay2.override_kernel_check` will bypass the check.

The default root and fallback directories respectively are
`/var/lib/docker/loopback/root` and
`/var/lib/docker/loopback/private`.

### Information on `docker info`

`docker info` when using the `loop_overlay2` storage driverw ill display
something like:

	$ sudo docker info
	[...]
	Storage Driver: loop_overlay2
	 Backing Filesystem: xfs
	 Loopback Root Directory: /var/lib/docker/loopback/root
	 Loopback Fallback Directory: /var/lib/docker/loopback/fallback
	[...]

#### Status items

Each item in the indented section under `Storage Driver: loop_overlay2` are
status information about the driver.
 *  `Backing Filesystem` the filesystem type which is useed for the docker root (e.g. `/var/lib/docker`)
 *  `Loopback Root Directory` where images layers are stored (if allowed by filesystem and access permissions)
 *  `Loopback Fallback Directory` directory to use as a fallback if locating or creating a layer in root directory fails

### About the loop_overlay2 options

The loop_overlay2 backend supports some options that you can specify
when starting the Docker daemon using the `--storage-opt` flags.
This uses the `loop_overlay2` prefix and would be used something like
`docker daemon --storage-opt loop_overlay2.foo=bar`.

These options are currently documented both in [the man
page](../../../man/docker.1.md) and in [the online
documentation](https://docs.docker.com/reference/commandline/daemon/#storage-driver-options).
If you add an option, update both the `man` page and the documentation.
