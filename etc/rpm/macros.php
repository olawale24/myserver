#
# Interface versions exposed by PHP:
# 
%php_core_api 20100412-64
%php_zend_api 20100525-64
%php_pdo_api  20080721-64
%php_version  5.4.16

%php_extdir    %{_libdir}/php/modules

%php_inidir    %{_sysconfdir}/php.d

%php_incldir    %{_includedir}/php

%__php         %{_bindir}/php
