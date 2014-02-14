install(FILES breeder.conf.example DESTINATION ${SYSCONF_INSTALL_DIR}/ProjectRiddle RENAME breeder.conf)
configure_file(configPath.h.in ${CMAKE_BINARY_DIR}/config/configPath.h)
