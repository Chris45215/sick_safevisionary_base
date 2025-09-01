#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "sick_safevisionary_base::sick_safevisionary_base" for configuration "Release"
set_property(TARGET sick_safevisionary_base::sick_safevisionary_base APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(sick_safevisionary_base::sick_safevisionary_base PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/sick_safevisionary_base.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/sick_safevisionary_base.dll"
  )

list(APPEND _cmake_import_check_targets sick_safevisionary_base::sick_safevisionary_base )
list(APPEND _cmake_import_check_files_for_sick_safevisionary_base::sick_safevisionary_base "${_IMPORT_PREFIX}/lib/sick_safevisionary_base.lib" "${_IMPORT_PREFIX}/bin/sick_safevisionary_base.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
