Branches used in this repo
==========================

The document explains the branching structure that we are using in the VFSForGit repository as well as the forking strategy that we have adopted for contributing.

Repo Branches
-------------

1. master

    This will track the Git for Windows repository master branch

2. vfs

    Would like to use this branch as an ever-green branch that continually rebases the VFSForGit changes onto a windows ever-green branch that is on the core/master, so that we can detect when the patches for VFSForGit have issues or if we have a new version patches sent upstream git we can regenerate this branch.

3. vs/master

    This tracks with the Git for Windows repository vs/master branch and are the generated files for using a Visual Studio solution.

4. vfs-#

    These branches are used to track the specific version that match Git for Windows with the VFSForGit specific patches on top.  When a new version of Git for Windows is released, the VFSForGit patches will be rebased on that windows version and a new gvfs-# branch created to create pull requests against.

    #### Examples

    ```
    vfs-2.20.0
    vfs-2.20.1
    ```

    The versions of git for VFSForGit are based on the Git for Windows versions.  v2.20.0.vfs.1 will correspond with the v2.20.0.windows.1 with the VFSForGit specific patches applied to the windows version.

Tags
----

We are using annotated tags to build the version number for git.  The build will look back through the commit history to find the first tag matching `v[0-9]*vfs*` and build the git version number using that tag.

Forking
-------

A personal fork of this repository and a branch in that repository should be used for development.

These branches should be based on the latest vfs-# branch.  If there are work in progress pull requests that you have based on a previous version branch when a new version branch is created, you will need to move your patches to the new branch to get them in that latest version.

#### Example

```
git clone <personal fork repo URL>
git remote add ms https://github.com/Microsoft/git.git
git checkout -b my-changes ms/vfs-2.20.0 --no-track
git push -fu origin HEAD
```
