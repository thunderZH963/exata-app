#
# This Makefile is for QualNet on 32bit Windows XP and Windows Vista, using
# Microsoft Visual Studio 2010 and Microsoft Visual C++ 2010 Express.
#
# Use nmake.exe provided with Visual C++.
# (nmake.exe must be in your PATH.)
#
# Instructions:
#
# (1) Copy Makefile-windows-vc10 to Makefile.
# (2) Run "nmake".
#
# Or, run "nmake -f Makefile-windows-vc10".
#
# Please note that nmake does not behave like GNU make in many respects:
#
# (1) nmake requires macros to be defined before they are used, unlike 
#     GNU make.
# (2) nmake accepts re-defining macros (GNU make does this using +=, but
#     with nmake you can just define the macro again).  You can also use
#     the first definition of the macro in the redefinition of the macro.
# (3) None of the GNU make control flow semantics are present.
#
# Tested successfully on:
# Windows XP and Windows Vista with Microsoft Visual Studio 2010 and 
# Microsoft Visual C++ 2010 Express
#
# For a list of supported platforms and compilers, please visit http://www.scalable-networks.com/content/products/technology-overview
#

ARCH = windows
COMPILER = vc10

#
# Create the first rule in the Makefile, for target "all".  nmake, when
# given no target, defaults to the target in the first rule.
#

include Makefile-windows-first-target
#include Makefile-windows-exata-first-target

#
# Include addons
#

include Makefile-addons-windows

#
# Load rules for Windows platforms.
#

include Makefile-windows-common

CXXFLAGS = \
/EHsc /MT /nologo \
$(INCLUDE_DIRS) \
$(FLAGS) \
$(DEBUG) \
$(OPT) \
-D_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES \
$(ADDON_OPTIONS)

#
# Add WinNT-specific socket library to existing LIBS definition.
#

LIBS = $(LIBS) ws2_32.lib

#
# Define active optimization, debugging flags.
#
# Debugging works best when optimizations are off (uncomment the DEBUG
# macro, comment out the OPT macro, then nmake clean and nmake).
#

FLAGS = $(FLAGS) -DPARALLEL -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -D_SECURE_SCL=0 -D_HAS_ITERATOR_DEBUGGING=0
##DEBUG = /Zi 
OPT = /Ox /Ob2

#
# Define remaining targets.
# These rules need to be listed last, since nmake will not use macro
# values -- such as $(OPT) and $(DEBUG) -- unless they are defined
# before the rules for targets (unlike GNU make).
#

include Makefile-windows-targets

#
# Uncomment the lines below if modifying kernel source code.  These add
# additional targets for recompilation.  Customers will not have this option.
#

#include ../kernel/src/Makefile-windows
###include ../addons/kernel/Makefile-windows
