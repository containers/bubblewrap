bubblewrap release checklist
============================

* Collect release notes
* Update version number in `configure.ac` **and** `meson.build`
* Commit the changes
* `make distcheck`
* Do any final smoke-testing, e.g. update a package, install and test it
* `git evtag sign v$VERSION`
    * Include the release notes in the tag message
* `git push --atomic origin main v$VERSION`
* https://github.com/containers/bubblewrap/releases/new
    * Fill in the new version's tag in the "Tag version" box
    * Title: `$VERSION`
    * Copy the release notes into the description
    * Upload the tarball that you built with `make distcheck`
    * Get the `sha256sum` of the tarball and append it to the description
    * `Publish release`
