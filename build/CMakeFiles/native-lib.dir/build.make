# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/roan/Desktop/solution3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/roan/Desktop/solution3/build

# Include any dependencies generated for this target.
include CMakeFiles/native-lib.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/native-lib.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/native-lib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/native-lib.dir/flags.make

CMakeFiles/native-lib.dir/NativeHasher.cpp.o: CMakeFiles/native-lib.dir/flags.make
CMakeFiles/native-lib.dir/NativeHasher.cpp.o: ../NativeHasher.cpp
CMakeFiles/native-lib.dir/NativeHasher.cpp.o: CMakeFiles/native-lib.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/roan/Desktop/solution3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/native-lib.dir/NativeHasher.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/native-lib.dir/NativeHasher.cpp.o -MF CMakeFiles/native-lib.dir/NativeHasher.cpp.o.d -o CMakeFiles/native-lib.dir/NativeHasher.cpp.o -c /home/roan/Desktop/solution3/NativeHasher.cpp

CMakeFiles/native-lib.dir/NativeHasher.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/native-lib.dir/NativeHasher.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/roan/Desktop/solution3/NativeHasher.cpp > CMakeFiles/native-lib.dir/NativeHasher.cpp.i

CMakeFiles/native-lib.dir/NativeHasher.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/native-lib.dir/NativeHasher.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/roan/Desktop/solution3/NativeHasher.cpp -o CMakeFiles/native-lib.dir/NativeHasher.cpp.s

# Object files for target native-lib
native__lib_OBJECTS = \
"CMakeFiles/native-lib.dir/NativeHasher.cpp.o"

# External object files for target native-lib
native__lib_EXTERNAL_OBJECTS =

libnative-lib.so: CMakeFiles/native-lib.dir/NativeHasher.cpp.o
libnative-lib.so: CMakeFiles/native-lib.dir/build.make
libnative-lib.so: CMakeFiles/native-lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/roan/Desktop/solution3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libnative-lib.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/native-lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/native-lib.dir/build: libnative-lib.so
.PHONY : CMakeFiles/native-lib.dir/build

CMakeFiles/native-lib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/native-lib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/native-lib.dir/clean

CMakeFiles/native-lib.dir/depend:
	cd /home/roan/Desktop/solution3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/roan/Desktop/solution3 /home/roan/Desktop/solution3 /home/roan/Desktop/solution3/build /home/roan/Desktop/solution3/build /home/roan/Desktop/solution3/build/CMakeFiles/native-lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/native-lib.dir/depend
