from distutils.core  import setup, Extension
from Cython.Build import cythonize, build_ext

extensions = [Extension("*", ["*.pyx"])]

setup(name='fextractor',
      include_dirs=["."],
      zip_safe=False,
      packages=["."],
      ext_modules=cythonize(extensions),
      build_ext=build_ext
)
