diff --git a/configure b/configure
index 91a7f3b..ba97dbc 100755
--- a/configure
+++ b/configure
@@ -663,6 +663,7 @@ MPM_LIB
 progname
 MOD_SO_LDADD
 INSTALL_DSO
+MOD_REQFILTER_LDADD
 MOD_REWRITE_LDADD
 MOD_ALIAS_LDADD
 MOD_USERDIR_LDADD
@@ -985,6 +986,7 @@ enable_speling
 enable_userdir
 enable_alias
 enable_rewrite
+enable_reqfilter
 enable_so
 with_program_name
 with_suexec_bin
@@ -6652,7 +6654,7 @@ if test "${apu_found}" = "yes"; then
 
 
 ap_ckver_CPPFLAGS="$CPPFLAGS"
-CPPFLAGS="$CPPFLAGS `$apu_config --includes`"
+CPPFLAGS="$CPPFLAGS `$apu_config --includes` `$apr_config --includes`"
 
 { $as_echo "$as_me:${as_lineno-$LINENO}: checking for APR-util version 1.2.0 or later" >&5
 $as_echo_n "checking for APR-util version 1.2.0 or later... " >&6; }
@@ -10179,6 +10181,20 @@ EOF
   > $modpath_current/modules.mk
 
 
+  MODLIST="$MODLIST reqfilter"
+  objects="mod_reqfilter.lo"
+
+  # The filename of a convenience library must have a "lib" prefix:
+  libname="libmod_reqfilter.la"
+  BUILTIN_LIBS="$BUILTIN_LIBS $modpath_current/$libname"
+  modpath_static="$modpath_static $libname"
+  cat >>$modpath_current/modules.mk<<EOF
+$libname: $objects
+	\$(MOD_LINK) $objects \$(MOD_REQFILTER_LDADD)
+EOF
+
+
+APACHE_VAR_SUBST="$APACHE_VAR_SUBST MOD_REQFILTER_LDADD"
 
   { $as_echo "$as_me:${as_lineno-$LINENO}: checking whether to enable mod_reqtimeout" >&5
 $as_echo_n "checking whether to enable mod_reqtimeout... " >&6; }
@@ -17321,8 +17337,6 @@ EOF
   test -d mappers || $srcdir/build/mkdir.sh $modpath_current
   > $modpath_current/modules.mk
 
-
-
   { $as_echo "$as_me:${as_lineno-$LINENO}: checking whether to enable mod_vhost_alias" >&5
 $as_echo_n "checking whether to enable mod_vhost_alias... " >&6; }
     # Check whether --enable-vhost-alias was given.
