# How to contribute

There are a few guidelines that we need contributors to follow so that we are able to process requests as efficiently as possible. If you have any questions or concerns please feel free to contact us at [opensource@metlife.com](mailto:opensource@metlife.com).

We welcome contributions as patches for new or existing issues and functionality via pull requests. This is particularly the case for simple fixes, such as typos or tweaks to documentation, which do not require a heavy investment of time and attention.

# Opening Issues

We appreciate being notified of problems with the code. We prefer that issues be filed the on Github Issue Tracker, rather than on social media or by direct email to the developers.

Please verify that your issue is not being currently addressed by other issues or pull requests by using the GitHub search tool to look for key words in the project issue tracker.

## Getting Started

* Review our [Code of Conduct](https://github.com/MetLife/metlife.github.io/blob/master/CONDUCT.md)
* Make sure you have a [GitHub account](https://github.com/signup/free)
* Submit a ticket for your issue, assuming one does not already exist.
  * Clearly describe the issue including steps to reproduce when it is a bug.
  * Make sure you fill in the earliest version that you know has the issue.
* Fork the repository on GitHub

## Making Changes

* Create a topic branch off of `master` before you start your work.
  * Please avoid working directly on the `master` branch.
* Make commits of logical units.
  * You may be asked to squash unnecessary commits down to logical units.
* Check for unnecessary whitespace with `git diff --check` before committing.
* Write meaningful, descriptive commit messages.
* Please follow existing code conventions when working on a file.

## Submitting Changes

* Push your changes to a topic branch in your fork of the repository.
* Submit a pull request to the repository in the MetLife organization.
* After feedback has been given we expect responses within two weeks. After two weeks we may close the pull request if it isn't showing any activity.
* Bug fixes or features that lack appropriate tests may not be considered for merge.
* Changes that lower test coverage may not be considered for merge.

## Pull Request Checklist

* If your pull request addresses an issue, please use the pull request title to describe the issue and mention the issue number in the pull request description. This will make sure a link back to the original issue is created.
* Please prefix the title of incomplete contributions with [WIP] (to indicate a work in progress). WIPs may be useful to (1) indicate you are working on something to avoid duplicated work, (2) request broad review of functionality or API, or (3) seek collaborators.
* All other tests pass when everything is rebuilt from scratch.
* When adding additional functionality, provide at least one example script or use case.
* Documentation is necessary for enhancements to be accepted.

# Additional Resources

* [General GitHub documentation](https://help.github.com/)
* [GitHub pull request documentation](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests)
* [MetLife's Code of Conduct](https://github.com/MetLife/metlife.github.io/blob/master/CONDUCT.md)