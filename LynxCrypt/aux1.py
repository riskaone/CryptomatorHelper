import pkg_resources
installed_packages = [pkg.key for pkg in pkg_resources.working_set]
'pycryptomator' in installed_packages