from setuptools import setup, find_packages

import openmaps_auth

with open('README.md', 'rt') as fh:
    long_description = fh.read()

with open('requirements/base.in', 'rt') as fh:
    install_requires = fh.read().split()
    
setup(name='openmaps_auth',
      version=openmaps_auth.__version__,
      author='Justin Bronn',
      author_email='justin.bronn@maxar.com',
      description='OpenMaps Authentication API',
      url='https://github.com/radiant-maxar/openmaps-auth',
      install_requires=install_requires,
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Web Environment',
          'Framework :: Django',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
      ],
)
