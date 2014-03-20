/* include/autoconf.h.  Generated from autoconf.h.in by configure.  */
/* include/autoconf.h.in.  Generated from configure.ac by autoheader.  */

/* avoid warnings on Android */
#ifdef HAVE_ANDROID_OS
# undef /*XXX protect against redefinition */ HAVE_SCHED_SETSCHEDULER
# undef /*XXX protect against redefinition */ HAVE_MALLOC_H
#endif /* HAVE_ANDROID_OS */


/* we are Dante */
#define BAREFOOTD 0

/* we are Dante */
#define COVENANT 0

/* Features enabled in build */
#define DANTE_BUILD "debug livedebug mon-data mon-disconnect preload sess2"

/* Compat functions enabled in build */
#define DANTE_COMPATFILES "issetugid setproctitle strlcpy strvis"

/* IPV4 level socket options enabled in build */
#define DANTE_SOCKOPTS_IPV4 "IP_FREEBIND IP_MINTTL IP_MTU_DISCOVER IP_TOS IP_TTL"

/* IPV6 level socket options enabled in build */
#define DANTE_SOCKOPTS_IPV6 "IPV6_ADDRFORM IPV6_UNICAST_HOPS IPV6_MULTICAST_LOOP IPV6_2292DSTOPTS IPV6_2292HOPLIMIT IPV6_2292HOPOPTS IPV6_2292PKTINFO IPV6_2292PKTOPTIONS IPV6_2292RTHDR IPV6_ADDRFORM IPV6_ADD_MEMBERSHIP IPV6_AUTHHDR IPV6_CHECKSUM IPV6_DROP_MEMBERSHIP IPV6_DSTOPTS IPV6_DSTOPTS IPV6_HOPLIMIT IPV6_HOPLIMIT IPV6_HOPOPTS IPV6_HOPOPTS IPV6_IPSEC_POLICY IPV6_JOIN_ANYCAST IPV6_JOIN_GROUP IPV6_LEAVE_ANYCAST IPV6_LEAVE_GROUP IPV6_MTU IPV6_MTU_DISCOVER IPV6_MULTICAST_HOPS IPV6_MULTICAST_IF IPV6_MULTICAST_LOOP IPV6_NEXTHOP IPV6_PKTINFO IPV6_RECVDSTOPTS IPV6_RECVERR IPV6_RECVHOPLIMIT IPV6_RECVHOPOPTS IPV6_RECVPKTINFO IPV6_RECVRTHDR IPV6_RECVTCLASS IPV6_ROUTER_ALERT IPV6_RTHDR IPV6_RTHDRDSTOPTS IPV6_TCLASS IPV6_UNICAST_HOPS IPV6_V6ONLY IPV6_XFRM_POLICY"

/* Socket level socket options enabled in build */
#define DANTE_SOCKOPTS_SO "SO_BROADCAST SO_DEBUG SO_DONTROUTE SO_KEEPALIVE SO_LINGER SO_OOBINLINE SO_PRIORITY SO_RCVBUF SO_RCVBUFFORCE SO_RCVLOWAT SO_RCVTIMEO SO_SNDBUF SO_SNDBUFFORCE SO_SNDLOWAT SO_SNDTIMEO SO_TIMESTAMP"

/* TCP level socket options enabled in build */
#define DANTE_SOCKOPTS_TCP "TCP_CORK TCP_KEEPCNT TCP_KEEPIDLE TCP_KEEPINTVL TCP_LINGER2 TCP_MAXSEG TCP_MD5SIG TCP_NODELAY TCP_SYNCNT TCP_WINDOW_CLAMP"

/* UDP level socket options enabled in build */
#define DANTE_SOCKOPTS_UDP "UDP_CORK"

/* for debugging */
#define DIAGNOSTIC 0

/* dlopen has RTLD_ prefix */
#define DL_LAZY RTLD_LAZY

/* ignore FD_SETSIZE */
#define FD_SETSIZE_LIMITS_SELECT 0

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define to 1 if you have the `backtrace' function. */
#define HAVE_BACKTRACE 1

/* Define to 1 if you have the `bindresvport' function. */
#define HAVE_BINDRESVPORT 1

/* platform bug */
/* #undef HAVE_BROKEN_INET_NTOA */

/* BSD Authentication support */
/* #undef HAVE_BSDAUTH */

/* Define to 1 if you have the <bsd_auth.h> header file. */
/* #undef HAVE_BSD_AUTH_H */

/* Define to 1 if you have the `bzero' function. */
#define HAVE_BZERO 1

/* monotonic clock_gettime() */
#define HAVE_CLOCK_GETTIME_MONOTONIC 1

/* struct cmsghdr exists */
#define HAVE_CMSGHDR 1

/* CMSG_LEN exists */
#define HAVE_CMSG_LEN 1

/* CMSG_SPACE exists */
#define HAVE_CMSG_SPACE 1

/* Define to 1 if you have the <com_err.h> header file. */
/* #undef HAVE_COM_ERR_H */

/* Define to 1 if you have com_err in krb5.h */
/* #undef HAVE_COM_ERR_IN_KRB5 */

/* use tcpwrappers */
/* #undef HAVE_COND_LIBWRAP */

/* low-overhead debugging enabled */
#define HAVE_COND_LIVEDEBUG 1

/* PAM support */
/* #undef HAVE_COND_PAM */

/* Disable environment variables */
/* #undef HAVE_CONFENV_DISABLE */

/* CPU_EQUAL exists in sched.h */
#define HAVE_CPU_EQUAL 1

/* Define to 1 if you have the <crypt.h> header file. */
#define HAVE_CRYPT_H 1

/* Define to 1 if you have the `daemon' function. */
#define HAVE_DAEMON 1

/* enable darwin/osx workarounds */
/* #undef HAVE_DARWIN */

/* __attribute__ macro support */
#define HAVE_DECL_ATTRIBUTE 1

/* __bounded__ macro support */
/* #undef HAVE_DECL_BOUNDED */

/* format attribute support */
#define HAVE_DECL_FORMAT 1

/* Define to 1 if you have the declaration of `krb5_kt_free_entry', and to 0
   if you don't. */
/* #undef HAVE_DECL_KRB5_KT_FREE_ENTRY */

/* __nunnull__ attribute support */
/* #undef HAVE_DECL_NONNULL */

/* DEC workarounds */
/* #undef HAVE_DEC_PROTO */

/* Define to 1 if you have the `difftime' function. */
#define HAVE_DIFFTIME 1

/* dlfcn.h exists */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* option count */
#define HAVE_DUPSOCKOPT_MAX 23

/* using pidfile for server */
#define HAVE_ENABLED_PIDFILE 1

/* Define to 1 if you have error_message */
/* #undef HAVE_ERROR_MESSAGE */

/* Define to 1 if you have the <et/com_err.h> header file. */
/* #undef HAVE_ET_COM_ERR_H */

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* DEC workarounds */
/* #undef HAVE_EXTRA_OSF_SYMBOLS */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* no fd_mask definition */
#define HAVE_FDMASK 1

/* Define to 1 if you have the `freeaddrinfo' function. */
#define HAVE_FREEADDRINFO 1

/* Define to 1 if you have the `freeifaddrs' function. */
#define HAVE_FREEIFADDRS 1

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `gethostbyname2' function. */
#define HAVE_GETHOSTBYNAME2 1

/* Define to 1 if you have the `getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* Define to 1 if you have the `getipnodebyname' function. */
/* #undef HAVE_GETIPNODEBYNAME */

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define to 1 if you have the `getpass' function. */
#define HAVE_GETPASS 1

/* Define to 1 if you have the `getprpwnam' function. */
/* #undef HAVE_GETPRPWNAM */

/* Define to 1 if you have the `getspnam' function. */
#define HAVE_GETSPNAM 1

/* Define to 1 if you have krb5_get_init_creds_keytab */
/* #undef HAVE_GET_INIT_CREDS_KEYTAB */

/* Define to 1 if you have krb5_get_init_creds_opt_alloc */
/* #undef HAVE_GET_INIT_CREDS_OPT_ALLOC */

/* Define to 1 if you have krb5_get_init_creds_opt_free with krb5 context */
/* #undef HAVE_GET_INIT_CREDS_OPT_FREE_CTX */

/* GSSAPI support */
/* #undef HAVE_GSSAPI */

/* Define to 1 if you have the <gssapi/gssapi_ext.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_EXT_H */

/* Define to 1 if you have the <gssapi/gssapi_generic.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_GENERIC_H */

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_H */

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_KRB5_H */

/* Define to 1 if you have the <gssapi.h> header file. */
/* #undef HAVE_GSSAPI_H */

/* Heimdal kerberos implementation */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define to 1 if you have the `hstrerror' function. */
#define HAVE_HSTRERROR 1

/* Define to 1 if you have the <ifaddrs.h> header file. */
#define HAVE_IFADDRS_H 1

/* in6_addr defined */
#define HAVE_IN6_ADDR 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if the system has the type `int16_t'. */
#define HAVE_INT16_T 1

/* Define to 1 if the system has the type `int32_t'. */
#define HAVE_INT32_T 1

/* Define to 1 if the system has the type `int8_t'. */
#define HAVE_INT8_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if the system has the type `in_addr_t'. */
#define HAVE_IN_ADDR_T 1

/* Define to 1 if the system has the type `in_port_t'. */
#define HAVE_IN_PORT_T 1

/* IPV6_2292DSTOPTS socket option */
#define HAVE_IPV6_2292DSTOPTS 1

/* IPV6_2292HOPLIMIT socket option */
#define HAVE_IPV6_2292HOPLIMIT 1

/* IPV6_2292HOPOPTS socket option */
#define HAVE_IPV6_2292HOPOPTS 1

/* IPV6_2292PKTINFO socket option */
#define HAVE_IPV6_2292PKTINFO 1

/* IPV6_2292PKTOPTIONS socket option */
#define HAVE_IPV6_2292PKTOPTIONS 1

/* IPV6_2292RTHDR socket option */
#define HAVE_IPV6_2292RTHDR 1

/* IPV6_ADDRFORM socket option */
#define HAVE_IPV6_ADDRFORM 1

/* IPV6_ADDR_PREFERENCES socket option */
/* #undef HAVE_IPV6_ADDR_PREFERENCES */

/* IPV6_ADD_MEMBERSHIP socket option */
#define HAVE_IPV6_ADD_MEMBERSHIP 1

/* IPV6_AUTHHDR socket option */
#define HAVE_IPV6_AUTHHDR 1

/* IPV6_AUTH_LEVEL socket option */
/* #undef HAVE_IPV6_AUTH_LEVEL */

/* IPV6_AUTOFLOWLABEL socket option */
/* #undef HAVE_IPV6_AUTOFLOWLABEL */

/* IPV6_CHECKSUM socket option */
#define HAVE_IPV6_CHECKSUM 1

/* IPV6_DONTFRAG socket option */
/* #undef HAVE_IPV6_DONTFRAG */

/* IPV6_DROP_MEMBERSHIP socket option */
#define HAVE_IPV6_DROP_MEMBERSHIP 1

/* IPV6_DSTOPTS socket option */
#define HAVE_IPV6_DSTOPTS 1

/* IPV6_ESP_NETWORK_LEVEL socket option */
/* #undef HAVE_IPV6_ESP_NETWORK_LEVEL */

/* IPV6_ESP_TRANS_LEVEL socket option */
/* #undef HAVE_IPV6_ESP_TRANS_LEVEL */

/* IPV6_FLOWINFO socket option */
/* #undef HAVE_IPV6_FLOWINFO */

/* IPV6_FLOWINFO_SEND socket option */
/* #undef HAVE_IPV6_FLOWINFO_SEND */

/* IPV6_FLOWLABEL_MGR socket option */
/* #undef HAVE_IPV6_FLOWLABEL_MGR */

/* IPV6_HOPLIMIT socket option */
#define HAVE_IPV6_HOPLIMIT 1

/* IPV6_HOPOPTS socket option */
#define HAVE_IPV6_HOPOPTS 1

/* IPV6_IPCOMP_LEVEL socket option */
/* #undef HAVE_IPV6_IPCOMP_LEVEL */

/* IPV6_IPSEC_POLICY socket option */
#define HAVE_IPV6_IPSEC_POLICY 1

/* IPV6_JOIN_ANYCAST socket option */
#define HAVE_IPV6_JOIN_ANYCAST 1

/* IPV6_JOIN_GROUP socket option */
#define HAVE_IPV6_JOIN_GROUP 1

/* IPV6_LEAVE_ANYCAST socket option */
#define HAVE_IPV6_LEAVE_ANYCAST 1

/* IPV6_LEAVE_GROUP socket option */
#define HAVE_IPV6_LEAVE_GROUP 1

/* IPV6_MINHOPCOUNT socket option */
/* #undef HAVE_IPV6_MINHOPCOUNT */

/* IPV6_MTU socket option */
#define HAVE_IPV6_MTU 1

/* IPV6_MTU_DISCOVER socket option */
#define HAVE_IPV6_MTU_DISCOVER 1

/* IPV6_MULTICAST_HOPS socket option */
#define HAVE_IPV6_MULTICAST_HOPS 1

/* IPV6_MULTICAST_IF socket option */
#define HAVE_IPV6_MULTICAST_IF 1

/* IPV6_MULTICAST_LOOP socket option */
#define HAVE_IPV6_MULTICAST_LOOP 1

/* IPV6_NEXTHOP socket option */
#define HAVE_IPV6_NEXTHOP 1

/* IPV6_ORIGDSTADDR socket option */
/* #undef HAVE_IPV6_ORIGDSTADDR */

/* IPV6_PATHMTU socket option */
/* #undef HAVE_IPV6_PATHMTU */

/* IPV6_PIPEX socket option */
/* #undef HAVE_IPV6_PIPEX */

/* IPV6_PKTINFO socket option */
#define HAVE_IPV6_PKTINFO 1

/* IPV6_PORTRANGE socket option */
/* #undef HAVE_IPV6_PORTRANGE */

/* IPV6_RECVDSTADDR socket option */
/* #undef HAVE_IPV6_RECVDSTADDR */

/* IPV6_RECVDSTOPTS socket option */
#define HAVE_IPV6_RECVDSTOPTS 1

/* IPV6_RECVERR socket option */
#define HAVE_IPV6_RECVERR 1

/* IPV6_RECVHOPLIMIT socket option */
#define HAVE_IPV6_RECVHOPLIMIT 1

/* IPV6_RECVHOPOPTS socket option */
#define HAVE_IPV6_RECVHOPOPTS 1

/* IPV6_RECVOPTS socket option */
/* #undef HAVE_IPV6_RECVOPTS */

/* IPV6_RECVORIGDSTADDR socket option */
/* #undef HAVE_IPV6_RECVORIGDSTADDR */

/* IPV6_RECVPATHMTU socket option */
/* #undef HAVE_IPV6_RECVPATHMTU */

/* IPV6_RECVPKTINFO socket option */
#define HAVE_IPV6_RECVPKTINFO 1

/* IPV6_RECVRETOPTS socket option */
/* #undef HAVE_IPV6_RECVRETOPTS */

/* IPV6_RECVRTHDR socket option */
#define HAVE_IPV6_RECVRTHDR 1

/* IPV6_RECVTCLASS socket option */
#define HAVE_IPV6_RECVTCLASS 1

/* IPV6_RETOPTS socket option */
/* #undef HAVE_IPV6_RETOPTS */

/* IPV6_ROUTER_ALERT socket option */
#define HAVE_IPV6_ROUTER_ALERT 1

/* IPV6_RTHDR socket option */
#define HAVE_IPV6_RTHDR 1

/* IPV6_RTHDRDSTOPTS socket option */
#define HAVE_IPV6_RTHDRDSTOPTS 1

/* ipv6 not supported currently */
#define HAVE_IPV6_SUPPORT 0

/* IPV6_TCLASS socket option */
#define HAVE_IPV6_TCLASS 1

/* IPV6_TRANSPARENT socket option */
/* #undef HAVE_IPV6_TRANSPARENT */

/* IPV6_UNICAST_HOPS socket option */
#define HAVE_IPV6_UNICAST_HOPS 1

/* IPV6_USE_MIN_MTU socket option */
/* #undef HAVE_IPV6_USE_MIN_MTU */

/* IPV6_V6ONLY socket option */
#define HAVE_IPV6_V6ONLY 1

/* IPV6_XFRM_POLICY socket option */
#define HAVE_IPV6_XFRM_POLICY 1

/* IP_AUTH_LEVEL socket option */
/* #undef HAVE_IP_AUTH_LEVEL */

/* IP_DONTFRAG socket option */
/* #undef HAVE_IP_DONTFRAG */

/* IP_ESP_NETWORK_LEVEL socket option */
/* #undef HAVE_IP_ESP_NETWORK_LEVEL */

/* IP_ESP_TRANS_LEVEL socket option */
/* #undef HAVE_IP_ESP_TRANS_LEVEL */

/* IP_FREEBIND socket option */
#define HAVE_IP_FREEBIND 1

/* IP_HDRINCL socket option */
#define HAVE_IP_HDRINCL 1

/* IP_IPCOMP_LEVEL socket option */
/* #undef HAVE_IP_IPCOMP_LEVEL */

/* IP_MINTTL socket option */
#define HAVE_IP_MINTTL 1

/* IP_MTU_DISCOVER socket option */
#define HAVE_IP_MTU_DISCOVER 1

/* IP_MULTICAST_IF socket option */
#define HAVE_IP_MULTICAST_IF 1

/* IP_MULTICAST_LOOP socket option */
#define HAVE_IP_MULTICAST_LOOP 1

/* IP_MULTICAST_TTL socket option */
#define HAVE_IP_MULTICAST_TTL 1

/* IP_OPTIONS socket option */
#define HAVE_IP_OPTIONS 1

/* IP_PORTRANGE socket option */
/* #undef HAVE_IP_PORTRANGE */

/* IP_RECVDSTADDR socket option */
/* #undef HAVE_IP_RECVDSTADDR */

/* IP_RECVIF socket option */
/* #undef HAVE_IP_RECVIF */

/* IP_RECVTOS socket option */
#define HAVE_IP_RECVTOS 1

/* IP_RECVTTL socket option */
#define HAVE_IP_RECVTTL 1

/* IP_TOS socket option */
#define HAVE_IP_TOS 1

/* IP_TTL socket option */
#define HAVE_IP_TTL 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* KRB5 support */
/* #undef HAVE_KRB5 */

/* Define to 1 if you have krb5_get_error_message */
/* #undef HAVE_KRB5_GET_ERROR_MESSAGE */

/* Define to 1 if you have krb5_get_err_text */
/* #undef HAVE_KRB5_GET_ERR_TEXT */

/* Define to 1 if you have the <krb5.h> header file. */
/* #undef HAVE_KRB5_H */

/* Define to 1 if you have krb5_kt_free_entry */
/* #undef HAVE_KRB5_KT_FREE_ENTRY */

/* Define to 1 if you have MEMORY: cache support */
/* #undef HAVE_KRB5_MEMORY_CACHE */

/* Define to 1 if you have the <lber.h> header file. */
/* #undef HAVE_LBER_H */

/* LDAP support */
/* #undef HAVE_LDAP */

/* Define to 1 if you have ldapssl_client_init */
/* #undef HAVE_LDAPSSL_CLIENT_INIT */

/* Define to 1 if you have the <ldap.h> header file. */
/* #undef HAVE_LDAP_H */

/* Define to 1 if you have LDAP_REBINDPROC_CALLBACK */
/* #undef HAVE_LDAP_REBINDPROC_CALLBACK */

/* Define to 1 if you have LDAP_REBIND_FUNCTION */
/* #undef HAVE_LDAP_REBIND_FUNCTION */

/* Define to 1 if you have LDAP_REBIND_PROC */
/* #undef HAVE_LDAP_REBIND_PROC */

/* Define to 1 if you have LDAP_SCOPE_DEFAULT */
/* #undef HAVE_LDAP_SCOPE_DEFAULT */

/* Define to 1 if you have ldap_url_desc2str */
/* #undef HAVE_LDAP_URL_DESC2STR */

/* Define to 1 if you have LDAPURLDesc.lud_scheme */
/* #undef HAVE_LDAP_URL_LUD_SCHEME */

/* Define to 1 if you have ldap_url_parse */
/* #undef HAVE_LDAP_URL_PARSE */

/* Define to 1 if you have the `asn1' library (-lasn1). */
/* #undef HAVE_LIBASN1 */

/* use libcfail */
/* #undef HAVE_LIBCFAIL */

/* Define to 1 if you have the `com_err' library (-lcom_err). */
/* #undef HAVE_LIBCOM_ERR */

/* Define to 1 if you have the `crypt' library (-lcrypt). */
#define HAVE_LIBCRYPT 1

/* Linux version of issetugid() */
#define HAVE_LIBC_ENABLE_SECURE 1

/* glibc variable disable */
/* #undef HAVE_LIBC_ENABLE_SECURE_DISABLED */

/* Define to 1 if you have the `des' library (-ldes). */
/* #undef HAVE_LIBDES */

/* Define to 1 if you have the `des425' library (-ldes425). */
/* #undef HAVE_LIBDES425 */

/* Define to 1 if you have the `gss' library (-lgss). */
/* #undef HAVE_LIBGSS */

/* Define to 1 if you have the `gssapi' library (-lgssapi). */
/* #undef HAVE_LIBGSSAPI */

/* Define to 1 if you have the `gssapi_krb5' library (-lgssapi_krb5). */
/* #undef HAVE_LIBGSSAPI_KRB5 */

/* Define to 1 if you have the `k5crypto' library (-lk5crypto). */
/* #undef HAVE_LIBK5CRYPTO */

/* Define to 1 if you have the `krb5' library (-lkrb5). */
/* #undef HAVE_LIBKRB5 */

/* Define to 1 if you have the `ksvc' library (-lksvc). */
/* #undef HAVE_LIBKSVC */

/* Define to 1 if you have the `lber' library (-llber). */
/* #undef HAVE_LIBLBER */

/* Define to 1 if you have the `ldap' library (-lldap). */
/* #undef HAVE_LIBLDAP */

/* Define to 1 if you have the `ldap60' library (-lldap60). */
/* #undef HAVE_LIBLDAP60 */

/* UPNP support library */
/* #undef HAVE_LIBMINIUPNP */

/* UPNP support library 1.3 */
/* #undef HAVE_LIBMINIUPNP13 */

/* UPNP support library 1.4 */
/* #undef HAVE_LIBMINIUPNP14 */

/* UPNP support library 1.7 */
/* #undef HAVE_LIBMINIUPNP17 */

/* Define to 1 if you have the `prldap60' library (-lprldap60). */
/* #undef HAVE_LIBPRLDAP60 */

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `resolv' library (-lresolv). */
/* #undef HAVE_LIBRESOLV */

/* Define to 1 if you have the `roken' library (-lroken). */
/* #undef HAVE_LIBROKEN */

/* Define to 1 if you have the `sasl2' library (-lsasl2). */
/* #undef HAVE_LIBSASL2 */

/* Define to 1 if you have the `ssldap60' library (-lssldap60). */
/* #undef HAVE_LIBSSLDAP60 */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* bug workaround */
#define HAVE_LINUX_BUGS 1

/* stdio function preloading */
/* #undef HAVE_LINUX_GLIBC_WORKAROUND */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* support for malloc debugging */
/* #undef HAVE_MALLOC_OPTIONS */

/* hostid size */
/* #undef HAVE_MAX_HOSTIDS */

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* module bandwidth installed */
/* #undef HAVE_MODULE_BANDWIDTH */

/* module checkmodule installed */
/* #undef HAVE_MODULE_CHECKMODULE */

/* module ldap installed */
/* #undef HAVE_MODULE_LDAP */

/* module redirect installed */
/* #undef HAVE_MODULE_REDIRECT */

/* Define to 1 if you have the `moncontrol' function. */
#define HAVE_MONCONTROL 1

/* Mozilla LDAP SDK support */
/* #undef HAVE_MOZILLA_LDAP_SDK */

/* Define to 1 if you have the <mozldap/ldap.h> header file. */
/* #undef HAVE_MOZLDAP_LDAP_H */

/* sys/socket.h defines MSG_WAITALL */
#define HAVE_MSG_WAITALL 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* netinet/ip.h header found */
#define HAVE_NETINET_IP_H 1

/* Define to 1 if you have the <netinet/ip_var.h> header file. */
/* #undef HAVE_NETINET_IP_VAR_H */

/* Define to 1 if you have the <netinet/tcp_fsm.h> header file. */
/* #undef HAVE_NETINET_TCP_FSM_H */

/* Define to 1 if you have the <net/if_dl.h> header file. */
/* #undef HAVE_NET_IF_DL_H */

/* realloc never calls malloc */
/* #undef HAVE_NOMALLOC_REALLOC */

/* free does not accept NULL parameter */
#define HAVE_NONULL_FREE 1

/* primitive platform */
/* #undef HAVE_NO_RESOLVESTUFF */

/* underscores not needed */
#define HAVE_NO_SYMBOL_UNDERSCORE 1

/* bug workaround */
/* #undef HAVE_OPENBSD_BUGS */

/* OpenLDAP support */
/* #undef HAVE_OPENLDAP */

/* openlog supports LOG_PERROR */
#define HAVE_OPENLOG_LOG_PERROR 1

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* platform pipe behavior */
/* #undef HAVE_PIPEBUFFER_RECV_BASED */

/* platform pipe behavior */
/* #undef HAVE_PIPEBUFFER_SEND_BASED */

/* platform pipe behavior */
#define HAVE_PIPEBUFFER_UNKNOWN 1

/* _Pragma() supported by compiler */
#define HAVE_PRAGMA_SUPPORT 1

/* Some privilege type supported */
/* #undef HAVE_PRIVILEGES */

/* Define to 1 if you have the <priv.h> header file. */
/* #undef HAVE_PRIV_H */

/* Define to 1 if you have the `processor_bind' function. */
/* #undef HAVE_PROCESSOR_BIND */

/* for profiling */
/* #undef HAVE_PROFILING */

/* programe name symbol exists */
#define HAVE_PROGNAME 1

/* proto */
#define HAVE_PROT_ACCEPT_0 int

/* proto */
#define HAVE_PROT_ACCEPT_1 int

/* proto */
#define HAVE_PROT_ACCEPT_2 struct sockaddr *

/* proto */
#define HAVE_PROT_ACCEPT_3 socklen_t *

/* proto */
#define HAVE_PROT_BIND_0 int

/* proto */
#define HAVE_PROT_BIND_1 int

/* proto */
#define HAVE_PROT_BIND_2 const struct sockaddr *

/* proto */
#define HAVE_PROT_BIND_3 socklen_t

/* proto */
#define HAVE_PROT_CONNECT_0 int

/* proto */
#define HAVE_PROT_CONNECT_1 int

/* proto */
#define HAVE_PROT_CONNECT_2 const struct sockaddr *

/* proto */
#define HAVE_PROT_CONNECT_3 socklen_t

/* proto */
#define HAVE_PROT_FCLOSE_0 int

/* proto */
#define HAVE_PROT_FCLOSE_1 FILE *

/* proto */
#define HAVE_PROT_FFLUSH_0 int

/* proto */
#define HAVE_PROT_FFLUSH_1 FILE *

/* proto */
#define HAVE_PROT_FGETC_0 int

/* proto */
#define HAVE_PROT_FGETC_1 FILE *

/* proto */
#define HAVE_PROT_FGETS_0 char *

/* proto */
#define HAVE_PROT_FGETS_1 char *

/* proto */
#define HAVE_PROT_FGETS_2 int

/* proto */
#define HAVE_PROT_FGETS_3 FILE *

/* proto */
#define HAVE_PROT_FPRINTF_0 int

/* proto */
#define HAVE_PROT_FPRINTF_1 FILE *

/* proto */
#define HAVE_PROT_FPRINTF_2 const char *

/* proto */
#define HAVE_PROT_FPRINTF_3 ...

/* proto */
#define HAVE_PROT_FPUTC_0 int

/* proto */
#define HAVE_PROT_FPUTC_1 int

/* proto */
#define HAVE_PROT_FPUTC_2 FILE *

/* proto */
#define HAVE_PROT_FPUTS_0 int

/* proto */
#define HAVE_PROT_FPUTS_1 const char *

/* proto */
#define HAVE_PROT_FPUTS_2 FILE *

/* proto */
#define HAVE_PROT_FREAD_0 size_t

/* proto */
#define HAVE_PROT_FREAD_1 void *

/* proto */
#define HAVE_PROT_FREAD_2 size_t

/* proto */
#define HAVE_PROT_FREAD_3 size_t

/* proto */
#define HAVE_PROT_FREAD_4 FILE *

/* proto */
#define HAVE_PROT_FWRITE_0 size_t

/* proto */
#define HAVE_PROT_FWRITE_1 const void *

/* proto */
#define HAVE_PROT_FWRITE_2 size_t

/* proto */
#define HAVE_PROT_FWRITE_3 size_t

/* proto */
#define HAVE_PROT_FWRITE_4 FILE *

/* proto */
#define HAVE_PROT_GETC_0 int

/* proto */
#define HAVE_PROT_GETC_1 FILE *

/* proto */
#define HAVE_PROT_GETHOSTBYADDR_0 struct hostent *

/* proto */
#define HAVE_PROT_GETHOSTBYADDR_1 const void *

/* proto */
#define HAVE_PROT_GETHOSTBYADDR_2 socklen_t

/* proto */
#define HAVE_PROT_GETHOSTBYADDR_3 int

/* proto */
#define HAVE_PROT_GETNAMEINFO_0 int

/* proto */
#define HAVE_PROT_GETNAMEINFO_1 const struct sockaddr *

/* proto */
#define HAVE_PROT_GETNAMEINFO_2 socklen_t

/* proto */
#define HAVE_PROT_GETNAMEINFO_3 char *

/* proto */
#define HAVE_PROT_GETNAMEINFO_4 socklen_t

/* proto */
#define HAVE_PROT_GETNAMEINFO_5 char *

/* proto */
#define HAVE_PROT_GETNAMEINFO_6 socklen_t

/* proto */
#define HAVE_PROT_GETNAMEINFO_7 int

/* proto */
#define HAVE_PROT_GETPEERNAME_0 int

/* proto */
#define HAVE_PROT_GETPEERNAME_1 int

/* proto */
#define HAVE_PROT_GETPEERNAME_2 struct sockaddr *

/* proto */
#define HAVE_PROT_GETPEERNAME_3 socklen_t *

/* proto */
#define HAVE_PROT_GETSOCKNAME_0 int

/* proto */
#define HAVE_PROT_GETSOCKNAME_1 int

/* proto */
#define HAVE_PROT_GETSOCKNAME_2 struct sockaddr *

/* proto */
#define HAVE_PROT_GETSOCKNAME_3 socklen_t *

/* proto */
#define HAVE_PROT_GETSOCKOPT_0 int

/* proto */
#define HAVE_PROT_GETSOCKOPT_1 int

/* proto */
#define HAVE_PROT_GETSOCKOPT_2 int

/* proto */
#define HAVE_PROT_GETSOCKOPT_3 int

/* proto */
#define HAVE_PROT_GETSOCKOPT_4 void *

/* proto */
#define HAVE_PROT_GETSOCKOPT_5 socklen_t *

/* proto */
#define HAVE_PROT_GETS_0 char *

/* proto */
#define HAVE_PROT_GETS_1 char *

/* proto */
#define HAVE_PROT_LISTEN_0 int

/* proto */
#define HAVE_PROT_LISTEN_1 int

/* proto */
#define HAVE_PROT_LISTEN_2 int

/* proto */
#define HAVE_PROT_PRINTF_0 int

/* proto */
#define HAVE_PROT_PRINTF_1 const char *

/* proto */
#define HAVE_PROT_PRINTF_2 ...

/* proto */
#define HAVE_PROT_PUTC_0 int

/* proto */
#define HAVE_PROT_PUTC_1 int

/* proto */
#define HAVE_PROT_PUTC_2 FILE *

/* proto */
#define HAVE_PROT_PUTS_0 int

/* proto */
#define HAVE_PROT_PUTS_1 const char *

/* proto */
#define HAVE_PROT_READV_0 ssize_t

/* proto */
#define HAVE_PROT_READV_1 int

/* proto */
#define HAVE_PROT_READV_2 const struct iovec *

/* proto */
#define HAVE_PROT_READV_3 int

/* proto */
#define HAVE_PROT_READ_0 ssize_t

/* proto */
#define HAVE_PROT_READ_1 int

/* proto */
#define HAVE_PROT_READ_2 void *

/* proto */
#define HAVE_PROT_READ_3 size_t

/* proto */
#define HAVE_PROT_RECVFROM_0 ssize_t

/* proto */
#define HAVE_PROT_RECVFROM_1 int

/* proto */
#define HAVE_PROT_RECVFROM_2 void *

/* proto */
#define HAVE_PROT_RECVFROM_3 size_t

/* proto */
#define HAVE_PROT_RECVFROM_4 int

/* proto */
#define HAVE_PROT_RECVFROM_5 struct sockaddr *

/* proto */
#define HAVE_PROT_RECVFROM_6 socklen_t *

/* proto */
#define HAVE_PROT_RECVMSG_0 ssize_t

/* proto */
#define HAVE_PROT_RECVMSG_1 int

/* proto */
#define HAVE_PROT_RECVMSG_2 struct msghdr *

/* proto */
#define HAVE_PROT_RECVMSG_3 int

/* proto */
#define HAVE_PROT_RECV_0 ssize_t

/* proto */
#define HAVE_PROT_RECV_1 int

/* proto */
#define HAVE_PROT_RECV_2 void *

/* proto */
#define HAVE_PROT_RECV_3 size_t

/* proto */
#define HAVE_PROT_RECV_4 int

/* proto */
#define HAVE_PROT_SENDMSG_0 ssize_t

/* proto */
#define HAVE_PROT_SENDMSG_1 int

/* proto */
#define HAVE_PROT_SENDMSG_2 const struct msghdr *

/* proto */
#define HAVE_PROT_SENDMSG_3 int

/* proto */
#define HAVE_PROT_SENDTO_0 ssize_t

/* proto */
#define HAVE_PROT_SENDTO_1 int

/* proto */
#define HAVE_PROT_SENDTO_2 const void *

/* proto */
#define HAVE_PROT_SENDTO_3 size_t

/* proto */
#define HAVE_PROT_SENDTO_4 int

/* proto */
#define HAVE_PROT_SENDTO_5 const struct sockaddr *

/* proto */
#define HAVE_PROT_SENDTO_6 socklen_t

/* proto */
#define HAVE_PROT_SEND_0 ssize_t

/* proto */
#define HAVE_PROT_SEND_1 int

/* proto */
#define HAVE_PROT_SEND_2 const void *

/* proto */
#define HAVE_PROT_SEND_3 size_t

/* proto */
#define HAVE_PROT_SEND_4 int

/* proto */
#define HAVE_PROT_VFPRINTF_0 int

/* proto */
#define HAVE_PROT_VFPRINTF_1 FILE *

/* proto */
#define HAVE_PROT_VFPRINTF_2 const char *

/* proto */
#define HAVE_PROT_VFPRINTF_3 va_list

/* proto */
#define HAVE_PROT_VPRINTF_0 int

/* proto */
#define HAVE_PROT_VPRINTF_1 const char *

/* proto */
#define HAVE_PROT_VPRINTF_2 va_list

/* proto */
#define HAVE_PROT_WRITEV_0 ssize_t

/* proto */
#define HAVE_PROT_WRITEV_1 int

/* proto */
#define HAVE_PROT_WRITEV_2 const struct iovec *

/* proto */
#define HAVE_PROT_WRITEV_3 int

/* proto */
#define HAVE_PROT_WRITE_0 ssize_t

/* proto */
#define HAVE_PROT_WRITE_1 int

/* proto */
#define HAVE_PROT_WRITE_2 const void *

/* proto */
#define HAVE_PROT_WRITE_3 size_t

/* proto */
#define HAVE_PROT__IO_GETC_0 int

/* proto */
#define HAVE_PROT__IO_GETC_1 FILE *

/* proto */
#define HAVE_PROT__IO_PUTC_0 int

/* proto */
#define HAVE_PROT__IO_PUTC_1 int

/* proto */
#define HAVE_PROT__IO_PUTC_2 FILE *

/* proto */
#define HAVE_PROT__READ_CHK_0 ssize_t

/* proto */
#define HAVE_PROT__READ_CHK_1 int

/* proto */
#define HAVE_PROT__READ_CHK_2 void *

/* proto */
#define HAVE_PROT__READ_CHK_3 size_t

/* proto */
#define HAVE_PROT__READ_CHK_4 size_t

/* working pselect() support */
#define HAVE_PSELECT 1

/* have pthread header */
#define HAVE_PTHREAD_H 1

/* readable buffer data */
#define HAVE_RECVBUF_IOCTL 1

/* Define to 1 if you have the <resolv.h> header file. */
#define HAVE_RESOLV_H 1

/* BSD type routing socket */
/* #undef HAVE_ROUTEINFO_BSD */

/* Linux type routing socket */
#define HAVE_ROUTEINFO_LINUX 1

/* routing socket communication supported */
#define HAVE_ROUTE_SOURCE 1

/* Define to 1 if you have the <rpc/rpc.h> header file. */
#define HAVE_RPC_RPC_H 1

/* Define to 1 if you have the `rresvport' function. */
#define HAVE_RRESVPORT 1

/* no working dlsym RTLD_NEXT */
#define HAVE_RTLD_NEXT 1

/* Have SASL support */
/* #undef HAVE_SASL */

/* Define to 1 if Mac Darwin without sasl.h */
/* #undef HAVE_SASL_DARWIN */

/* Define to 1 if you have the <sasl.h> header file. */
/* #undef HAVE_SASL_H */

/* Define to 1 if you have the <sasl/sasl.h> header file. */
/* #undef HAVE_SASL_SASL_H */

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* have sched_setaffinity */
#define HAVE_SCHED_SETAFFINITY 1

/* Define to 1 if you have the `sched_setscheduler' function. */
#define HAVE_SCHED_SETSCHEDULER 1

/* Define to 1 if you have the <security/pam_appl.h> header file. */
/* #undef HAVE_SECURITY_PAM_APPL_H */

/* max timeout value */
#define HAVE_SELECT_MAXTIMEOUT 0

/* send buffer data */
#define HAVE_SENDBUF_IOCTL TIOCOUTQ

/* bug workaround */
/* #undef HAVE_SENDMSG_DEADLOCK */

/* Define to 1 if you have the `setegid' function. */
#define HAVE_SETEGID 1

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the `setproctitle' function. */
/* #undef HAVE_SETPROCTITLE */

/* Define to 1 if you have the <shadow.h> header file. */
#define HAVE_SHADOW_H 1

/* signal.h defined SIGINFO */
/* #undef HAVE_SIGNAL_SIGINFO */

/* sig_atomic_t defined in signal.h */
#define HAVE_SIG_ATOMIC_T 1

/* missing MAC retrieval interface */
#define HAVE_SIOCGIFHWADDR 1

/* sa_len exists in sockaddr */
/* #undef HAVE_SOCKADDR_SA_LEN */

/* ss_len exists in sockaddr_storage */
/* #undef HAVE_SOCKADDR_STORAGE_SS_LEN */

/* Define to 1 if you have the `sockatmark' function. */
#define HAVE_SOCKATMARK 1

/* symbol count */
#define HAVE_SOCKOPTVALSYM_MAX 32

/* socket option count */
#define HAVE_SOCKOPTVAL_MAX 89

/* bug workaround */
/* #undef HAVE_SOLARIS_BUGS */

/* Solaris priv.h support */
/* #undef HAVE_SOLARIS_PRIVS */

/* SO_BINDANY socket option */
/* #undef HAVE_SO_BINDANY */

/* SO_BROADCAST socket option */
#define HAVE_SO_BROADCAST 1

/* SO_DEBUG socket option */
#define HAVE_SO_DEBUG 1

/* SO_DONTROUTE socket option */
#define HAVE_SO_DONTROUTE 1

/* SO_JUMBO socket option */
/* #undef HAVE_SO_JUMBO */

/* SO_KEEPALIVE socket option */
#define HAVE_SO_KEEPALIVE 1

/* SO_LINGER socket option */
#define HAVE_SO_LINGER 1

/* SO_OOBINLINE socket option */
#define HAVE_SO_OOBINLINE 1

/* SO_PRIORITY socket option */
#define HAVE_SO_PRIORITY 1

/* SO_RCVBUF socket option */
#define HAVE_SO_RCVBUF 1

/* SO_RCVBUFFORCE socket option */
#define HAVE_SO_RCVBUFFORCE 1

/* SO_RCVLOWAT socket option */
#define HAVE_SO_RCVLOWAT 1

/* SO_RCVTIMEO socket option */
#define HAVE_SO_RCVTIMEO 1

/* SO_REUSEADDR socket option */
#define HAVE_SO_REUSEADDR 1

/* SO_REUSEPORT socket option */
/* #undef HAVE_SO_REUSEPORT */

/* SO_SNDBUF socket option */
#define HAVE_SO_SNDBUF 1

/* SO_SNDBUFFORCE socket option */
#define HAVE_SO_SNDBUFFORCE 1

/* SO_SNDLOWAT socket option */
#define HAVE_SO_SNDLOWAT 1

/* SO_SNDTIMEO socket option */
#define HAVE_SO_SNDTIMEO 1

/* SO_TIMESTAMP socket option */
#define HAVE_SO_TIMESTAMP 1

/* SO_USELOOPBACK socket option */
/* #undef HAVE_SO_USELOOPBACK */

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* ip_opts defined in netinet/in.h */
/* #undef HAVE_STRUCT_IPOPTS */

/* Define to 1 if you have the `strvis' function. */
/* #undef HAVE_STRVIS */

/* Sun LDAP SDK support */
/* #undef HAVE_SUN_LDAP_SDK */

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* platform workaround */
/* #undef HAVE_SYSTEM_XMSG_MAGIC */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/ipc.h> header file. */
#define HAVE_SYS_IPC_H 1

/* Define to 1 if you have the <sys/pstat.h> header file. */
/* #undef HAVE_SYS_PSTAT_H */

/* sys/select.h needed */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/sem.h> header file. */
#define HAVE_SYS_SEM_H 1

/* Define to 1 if you have the <sys/shm.h> header file. */
#define HAVE_SYS_SHM_H 1

/* sys/sockio.h exists */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <tcpd.h> header file. */
/* #undef HAVE_TCPD_H */

/* TCP_CORK socket option */
#define HAVE_TCP_CORK 1

/* TCP_CWND socket option */
/* #undef HAVE_TCP_CWND */

/* tcp_info struct found in netinet/tcp.h */
#define HAVE_TCP_INFO 1

/* tcpi_advmss found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_ADVMSS 1

/* tcpi_ato found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_ATO 1

/* tcpi_backoff found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_BACKOFF 1

/* tcpi_ca_state found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_CA_STATE 1

/* tcpi_fackets found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_FACKETS 1

/* tcpi_last_ack_recv found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_LAST_ACK_RECV 1

/* tcpi_last_ack_sent found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_LAST_ACK_SENT 1

/* tcpi_last_data_recv found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_LAST_DATA_RECV 1

/* tcpi_last_data_sent found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_LAST_DATA_SENT 1

/* tcpi_lost found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_LOST 1

/* tcpi_pmtu found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_PMTU 1

/* tcpi_probes found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_PROBES 1

/* tcpi_rcv_rtt found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_RCV_RTT 1

/* tcpi_rcv_space found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_RCV_SPACE 1

/* tcpi_rcv_ssthresh found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_RCV_SSTHRESH 1

/* tcpi_reordering found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_REORDERING 1

/* tcpi_retrans found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_RETRANS 1

/* tcpi_retransmits found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_RETRANSMITS 1

/* tcpi_sacked found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_SACKED 1

/* tcpi_total_retrans found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_TOTAL_RETRANS 1

/* tcpi_unacked found in tcp_info struct */
#define HAVE_TCP_INFO_TCPI_UNACKED 1

/* TCP_INIT_CWND socket option */
/* #undef HAVE_TCP_INIT_CWND */

/* TCP_IPA socket option */
/* #undef HAVE_TCP_IPA */

/* TCP_KEEPCNT socket option */
#define HAVE_TCP_KEEPCNT 1

/* TCP_KEEPIDLE socket option */
#define HAVE_TCP_KEEPIDLE 1

/* TCP_KEEPINTVL socket option */
#define HAVE_TCP_KEEPINTVL 1

/* TCP_LINGER2 socket option */
#define HAVE_TCP_LINGER2 1

/* TCP_MAXRT socket option */
/* #undef HAVE_TCP_MAXRT */

/* TCP_MAXSEG socket option */
#define HAVE_TCP_MAXSEG 1

/* TCP_MD5SIG socket option */
#define HAVE_TCP_MD5SIG 1

/* TCP_NODELAY socket option */
#define HAVE_TCP_NODELAY 1

/* TCP_NOOPT socket option */
/* #undef HAVE_TCP_NOOPT */

/* TCP_NOPUSH socket option */
/* #undef HAVE_TCP_NOPUSH */

/* TCP_SACK_ENABLE socket option */
/* #undef HAVE_TCP_SACK_ENABLE */

/* TCP_STDURG socket option */
/* #undef HAVE_TCP_STDURG */

/* TCP_SYNCNT socket option */
#define HAVE_TCP_SYNCNT 1

/* TCP_WINDOW_CLAMP socket option */
#define HAVE_TCP_WINDOW_CLAMP 1

/* threads unstable platform */
/* #undef HAVE_THREADS_EINTR_PROBLEMS */

/* timeradd(), timersub etc. exist in sys/time.h */
#define HAVE_TIMER_MACROS 1

/* UDP_CORK socket option */
#define HAVE_UDP_CORK 1

/* Define to 1 if the system has the type `uint16_t'. */
#define HAVE_UINT16_T 1

/* Define to 1 if the system has the type `uint32_t'. */
#define HAVE_UINT32_T 1

/* Define to 1 if the system has the type `uint8_t'. */
#define HAVE_UINT8_T 1

/* unified vm buffers */
#define HAVE_UNIFIED_BUFFERCACHE 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if `utime(file, NULL)' sets file's timestamp to the present. */
#define HAVE_UTIME_NULL 1

/* Define to 1 if you have the <valgrind/valgrind.h> header file. */
/* #undef HAVE_VALGRIND_VALGRIND_H */

/* platform workaround */
/* #undef HAVE_VOLATILE_SIG_ATOMIC_T */

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the `vsyslog' function. */
#define HAVE_VSYSLOG 1

/* system V getpwnam */
/* #undef HAVE_WORKING_GETPWNAM */

/* Define to 1 if you have the `_IO_getc' function. */
#define HAVE__IO_GETC 1

/* Define to 1 if you have the `_IO_putc' function. */
#define HAVE__IO_PUTC 1

/* Define to 1 if you have the `__fprintf_chk' function. */
#define HAVE___FPRINTF_CHK 1

/* Define to 1 if you have the `__read_chk' function. */
#define HAVE___READ_CHK 1

/* Define to 1 if you have the `__vfprintf_chk' function. */
#define HAVE___VFPRINTF_CHK 1

/* Product name (lower case) */
#define LCPRODUCT "dante"

/* function loc */
/* #undef LIBRARY_ACCEPT */

/* function loc */
/* #undef LIBRARY_BIND */

/* function loc */
/* #undef LIBRARY_BINDRESVPORT */

/* function loc */
/* #undef LIBRARY_CONNECT */

/* function loc */
/* #undef LIBRARY_FREEADDRINFO */

/* function loc */
/* #undef LIBRARY_FREEHOSTENT */

/* function loc */
/* #undef LIBRARY_GETADDRINFO */

/* function loc */
/* #undef LIBRARY_GETHOSTBYADDR */

/* function loc */
/* #undef LIBRARY_GETHOSTBYNAME */

/* function loc */
/* #undef LIBRARY_GETHOSTBYNAME2 */

/* function loc */
/* #undef LIBRARY_GETIPNODEBYNAME */

/* function loc */
/* #undef LIBRARY_GETNAMEINFO */

/* function loc */
/* #undef LIBRARY_GETPEERNAME */

/* function loc */
/* #undef LIBRARY_GETSOCKNAME */

/* libc name */
#define LIBRARY_LIBC "libc.so.6"

/* libloc */
/* #undef LIBRARY_LIBNSL */

/* libloc */
/* #undef LIBRARY_LIBRESOLV */

/* libname */
/* #undef LIBRARY_LIBRPCSOC */

/* libloc */
/* #undef LIBRARY_LIBSOCKET */

/* function loc */
/* #undef LIBRARY_LISTEN */

/* libloc */
#define LIBRARY_PTHREAD "libpthread.so.0"

/* function loc */
/* #undef LIBRARY_RECV */

/* function loc */
/* #undef LIBRARY_RECVFROM */

/* function loc */
/* #undef LIBRARY_RECVMSG */

/* function loc */
/* #undef LIBRARY_RRESVPORT */

/* function loc */
/* #undef LIBRARY_SEND */

/* function loc */
/* #undef LIBRARY_SENDMSG */

/* function loc */
/* #undef LIBRARY_SENDTO */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Max number of errno values matching any alias keyword */
#define MAX_ERRNO_VALUES_FOR_SYMBOL 122

/* Max number of gataddrinfo() error values matching any alias keyword */
#define MAX_GAIERR_VALUES_FOR_SYMBOL 10

/* need AF_LOCAL definition */
/* #undef NEED_AF_LOCAL */

/* EXIT_FAILURE not defined in stdlib.h */
/* #undef NEED_EXIT_FAILURE */

/* getsockopt needs cast */
/* #undef NEED_GETSOCKOPT_CAST */

/* use SA_RESTART, not SV_INTERRUPT */
/* #undef NEED_SA_RESTART */

/* sys/sockio.h must be included */
/* #undef NEED_SYS_SOCKIO_H */

/* Name of package */
#define PACKAGE "dante"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* software prerelease */
#define PRERELEASE 0

/* Product name */
#define PRODUCT "Dante"

/* readable buffer ioctl */
#define RECVBUF_IOCTLVAL FIONREAD

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* send buffer ioctl */
#define SENDBUF_IOCTLVAL TIOCOUTQ

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* sockd config file */
#define SOCKD_CONFIGFILE "/etc/sockd.conf"

/* pid file location */
#define SOCKD_PIDFILE "/var/run/sockd.pid"

/* longest name + 1 */
#define SOCKOPTNAME_MAXLEN 21

/* socks config file */
#define SOCKS_CONFIGFILE "/etc/socks.conf"

/* do not use fallback */
#define SOCKS_DIRECTROUTE_FALLBACK 0

/* hostid option type */
/* #undef SOCKS_HOSTID_NAME */

/* no hostid support */
#define SOCKS_HOSTID_TYPE SOCKS_HOSTID_TYPE_NONE

/* IPV6_2292DSTOPTS IPv4 option */
#define SOCKS_IPV6_2292DSTOPTS_IPV4 0

/* IPV6_2292DSTOPTS IPv4 option */
#define SOCKS_IPV6_2292DSTOPTS_IPV6 1

/* IPV6_2292DSTOPTS protocol level */
#define SOCKS_IPV6_2292DSTOPTS_LVL IPPROTO_IPV6

/* IPV6_2292DSTOPTS value */
#define SOCKS_IPV6_2292DSTOPTS_NAME "ipv6_2292dstopts"

/* IPV6_2292HOPLIMIT IPv4 option */
#define SOCKS_IPV6_2292HOPLIMIT_IPV4 0

/* IPV6_2292HOPLIMIT IPv4 option */
#define SOCKS_IPV6_2292HOPLIMIT_IPV6 1

/* IPV6_2292HOPLIMIT protocol level */
#define SOCKS_IPV6_2292HOPLIMIT_LVL IPPROTO_IPV6

/* IPV6_2292HOPLIMIT value */
#define SOCKS_IPV6_2292HOPLIMIT_NAME "ipv6_2292hoplimit"

/* IPV6_2292HOPOPTS IPv4 option */
#define SOCKS_IPV6_2292HOPOPTS_IPV4 0

/* IPV6_2292HOPOPTS IPv4 option */
#define SOCKS_IPV6_2292HOPOPTS_IPV6 1

/* IPV6_2292HOPOPTS protocol level */
#define SOCKS_IPV6_2292HOPOPTS_LVL IPPROTO_IPV6

/* IPV6_2292HOPOPTS value */
#define SOCKS_IPV6_2292HOPOPTS_NAME "ipv6_2292hopopts"

/* IPV6_2292PKTINFO IPv4 option */
#define SOCKS_IPV6_2292PKTINFO_IPV4 0

/* IPV6_2292PKTINFO IPv4 option */
#define SOCKS_IPV6_2292PKTINFO_IPV6 1

/* IPV6_2292PKTINFO protocol level */
#define SOCKS_IPV6_2292PKTINFO_LVL IPPROTO_IPV6

/* IPV6_2292PKTINFO value */
#define SOCKS_IPV6_2292PKTINFO_NAME "ipv6_2292pktinfo"

/* IPV6_2292PKTOPTIONS IPv4 option */
#define SOCKS_IPV6_2292PKTOPTIONS_IPV4 0

/* IPV6_2292PKTOPTIONS IPv4 option */
#define SOCKS_IPV6_2292PKTOPTIONS_IPV6 1

/* IPV6_2292PKTOPTIONS protocol level */
#define SOCKS_IPV6_2292PKTOPTIONS_LVL IPPROTO_IPV6

/* IPV6_2292PKTOPTIONS value */
#define SOCKS_IPV6_2292PKTOPTIONS_NAME "ipv6_2292pktoptions"

/* IPV6_2292RTHDR IPv4 option */
#define SOCKS_IPV6_2292RTHDR_IPV4 0

/* IPV6_2292RTHDR IPv4 option */
#define SOCKS_IPV6_2292RTHDR_IPV6 1

/* IPV6_2292RTHDR protocol level */
#define SOCKS_IPV6_2292RTHDR_LVL IPPROTO_IPV6

/* IPV6_2292RTHDR value */
#define SOCKS_IPV6_2292RTHDR_NAME "ipv6_2292rthdr"

/* IPV6_ADDRFORM IPv4 option */
#define SOCKS_IPV6_ADDRFORM_IPV4 0

/* IPV6_ADDRFORM IPv4 option */
#define SOCKS_IPV6_ADDRFORM_IPV6 1

/* IPV6_ADDRFORM protocol level */
#define SOCKS_IPV6_ADDRFORM_LVL IPPROTO_IPV6

/* IPV6_ADDRFORM value */
#define SOCKS_IPV6_ADDRFORM_NAME "ipv6_addrform"

/* IPV6_ADDR_PREFERENCES IPv4 option */
/* #undef SOCKS_IPV6_ADDR_PREFERENCES_IPV4 */

/* IPV6_ADDR_PREFERENCES IPv4 option */
/* #undef SOCKS_IPV6_ADDR_PREFERENCES_IPV6 */

/* IPV6_ADDR_PREFERENCES protocol level */
/* #undef SOCKS_IPV6_ADDR_PREFERENCES_LVL */

/* IPV6_ADDR_PREFERENCES value */
/* #undef SOCKS_IPV6_ADDR_PREFERENCES_NAME */

/* IPV6_ADD_MEMBERSHIP IPv4 option */
#define SOCKS_IPV6_ADD_MEMBERSHIP_IPV4 0

/* IPV6_ADD_MEMBERSHIP IPv4 option */
#define SOCKS_IPV6_ADD_MEMBERSHIP_IPV6 1

/* IPV6_ADD_MEMBERSHIP protocol level */
#define SOCKS_IPV6_ADD_MEMBERSHIP_LVL IPPROTO_IPV6

/* IPV6_ADD_MEMBERSHIP value */
#define SOCKS_IPV6_ADD_MEMBERSHIP_NAME "ipv6_add_membership"

/* IPV6_AUTHHDR IPv4 option */
#define SOCKS_IPV6_AUTHHDR_IPV4 0

/* IPV6_AUTHHDR IPv4 option */
#define SOCKS_IPV6_AUTHHDR_IPV6 1

/* IPV6_AUTHHDR protocol level */
#define SOCKS_IPV6_AUTHHDR_LVL IPPROTO_IPV6

/* IPV6_AUTHHDR value */
#define SOCKS_IPV6_AUTHHDR_NAME "ipv6_authhdr"

/* IPV6_AUTH_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_AUTH_LEVEL_IPV4 */

/* IPV6_AUTH_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_AUTH_LEVEL_IPV6 */

/* IPV6_AUTH_LEVEL protocol level */
/* #undef SOCKS_IPV6_AUTH_LEVEL_LVL */

/* IPV6_AUTH_LEVEL value */
/* #undef SOCKS_IPV6_AUTH_LEVEL_NAME */

/* IPV6_AUTOFLOWLABEL IPv4 option */
/* #undef SOCKS_IPV6_AUTOFLOWLABEL_IPV4 */

/* IPV6_AUTOFLOWLABEL IPv4 option */
/* #undef SOCKS_IPV6_AUTOFLOWLABEL_IPV6 */

/* IPV6_AUTOFLOWLABEL protocol level */
/* #undef SOCKS_IPV6_AUTOFLOWLABEL_LVL */

/* IPV6_AUTOFLOWLABEL value */
/* #undef SOCKS_IPV6_AUTOFLOWLABEL_NAME */

/* IPV6_CHECKSUM IPv4 option */
#define SOCKS_IPV6_CHECKSUM_IPV4 0

/* IPV6_CHECKSUM IPv4 option */
#define SOCKS_IPV6_CHECKSUM_IPV6 1

/* IPV6_CHECKSUM protocol level */
#define SOCKS_IPV6_CHECKSUM_LVL IPPROTO_IPV6

/* IPV6_CHECKSUM value */
#define SOCKS_IPV6_CHECKSUM_NAME "ipv6_checksum"

/* IPV6_DONTFRAG IPv4 option */
/* #undef SOCKS_IPV6_DONTFRAG_IPV4 */

/* IPV6_DONTFRAG IPv4 option */
/* #undef SOCKS_IPV6_DONTFRAG_IPV6 */

/* IPV6_DONTFRAG protocol level */
/* #undef SOCKS_IPV6_DONTFRAG_LVL */

/* IPV6_DONTFRAG value */
/* #undef SOCKS_IPV6_DONTFRAG_NAME */

/* IPV6_DROP_MEMBERSHIP IPv4 option */
#define SOCKS_IPV6_DROP_MEMBERSHIP_IPV4 0

/* IPV6_DROP_MEMBERSHIP IPv4 option */
#define SOCKS_IPV6_DROP_MEMBERSHIP_IPV6 1

/* IPV6_DROP_MEMBERSHIP protocol level */
#define SOCKS_IPV6_DROP_MEMBERSHIP_LVL IPPROTO_IPV6

/* IPV6_DROP_MEMBERSHIP value */
#define SOCKS_IPV6_DROP_MEMBERSHIP_NAME "ipv6_drop_membership"

/* IPV6_DSTOPTS IPv4 option */
#define SOCKS_IPV6_DSTOPTS_IPV4 0

/* IPV6_DSTOPTS IPv4 option */
#define SOCKS_IPV6_DSTOPTS_IPV6 1

/* IPV6_DSTOPTS protocol level */
#define SOCKS_IPV6_DSTOPTS_LVL IPPROTO_IPV6

/* IPV6_DSTOPTS value */
#define SOCKS_IPV6_DSTOPTS_NAME "ipv6_dstopts"

/* IPV6_ESP_NETWORK_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_ESP_NETWORK_LEVEL_IPV4 */

/* IPV6_ESP_NETWORK_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_ESP_NETWORK_LEVEL_IPV6 */

/* IPV6_ESP_NETWORK_LEVEL protocol level */
/* #undef SOCKS_IPV6_ESP_NETWORK_LEVEL_LVL */

/* IPV6_ESP_NETWORK_LEVEL value */
/* #undef SOCKS_IPV6_ESP_NETWORK_LEVEL_NAME */

/* IPV6_ESP_TRANS_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_ESP_TRANS_LEVEL_IPV4 */

/* IPV6_ESP_TRANS_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_ESP_TRANS_LEVEL_IPV6 */

/* IPV6_ESP_TRANS_LEVEL protocol level */
/* #undef SOCKS_IPV6_ESP_TRANS_LEVEL_LVL */

/* IPV6_ESP_TRANS_LEVEL value */
/* #undef SOCKS_IPV6_ESP_TRANS_LEVEL_NAME */

/* IPV6_FLOWINFO IPv4 option */
/* #undef SOCKS_IPV6_FLOWINFO_IPV4 */

/* IPV6_FLOWINFO IPv4 option */
/* #undef SOCKS_IPV6_FLOWINFO_IPV6 */

/* IPV6_FLOWINFO protocol level */
/* #undef SOCKS_IPV6_FLOWINFO_LVL */

/* IPV6_FLOWINFO value */
/* #undef SOCKS_IPV6_FLOWINFO_NAME */

/* IPV6_FLOWINFO_SEND IPv4 option */
/* #undef SOCKS_IPV6_FLOWINFO_SEND_IPV4 */

/* IPV6_FLOWINFO_SEND IPv4 option */
/* #undef SOCKS_IPV6_FLOWINFO_SEND_IPV6 */

/* IPV6_FLOWINFO_SEND protocol level */
/* #undef SOCKS_IPV6_FLOWINFO_SEND_LVL */

/* IPV6_FLOWINFO_SEND value */
/* #undef SOCKS_IPV6_FLOWINFO_SEND_NAME */

/* IPV6_FLOWLABEL_MGR IPv4 option */
/* #undef SOCKS_IPV6_FLOWLABEL_MGR_IPV4 */

/* IPV6_FLOWLABEL_MGR IPv4 option */
/* #undef SOCKS_IPV6_FLOWLABEL_MGR_IPV6 */

/* IPV6_FLOWLABEL_MGR protocol level */
/* #undef SOCKS_IPV6_FLOWLABEL_MGR_LVL */

/* IPV6_FLOWLABEL_MGR value */
/* #undef SOCKS_IPV6_FLOWLABEL_MGR_NAME */

/* IPV6_HOPLIMIT IPv4 option */
#define SOCKS_IPV6_HOPLIMIT_IPV4 0

/* IPV6_HOPLIMIT IPv4 option */
#define SOCKS_IPV6_HOPLIMIT_IPV6 1

/* IPV6_HOPLIMIT protocol level */
#define SOCKS_IPV6_HOPLIMIT_LVL IPPROTO_IPV6

/* IPV6_HOPLIMIT value */
#define SOCKS_IPV6_HOPLIMIT_NAME "ipv6_hoplimit"

/* IPV6_HOPOPTS IPv4 option */
#define SOCKS_IPV6_HOPOPTS_IPV4 0

/* IPV6_HOPOPTS IPv4 option */
#define SOCKS_IPV6_HOPOPTS_IPV6 1

/* IPV6_HOPOPTS protocol level */
#define SOCKS_IPV6_HOPOPTS_LVL IPPROTO_IPV6

/* IPV6_HOPOPTS value */
#define SOCKS_IPV6_HOPOPTS_NAME "ipv6_hopopts"

/* IPV6_IPCOMP_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_IPCOMP_LEVEL_IPV4 */

/* IPV6_IPCOMP_LEVEL IPv4 option */
/* #undef SOCKS_IPV6_IPCOMP_LEVEL_IPV6 */

/* IPV6_IPCOMP_LEVEL protocol level */
/* #undef SOCKS_IPV6_IPCOMP_LEVEL_LVL */

/* IPV6_IPCOMP_LEVEL value */
/* #undef SOCKS_IPV6_IPCOMP_LEVEL_NAME */

/* IPV6_IPSEC_POLICY IPv4 option */
#define SOCKS_IPV6_IPSEC_POLICY_IPV4 0

/* IPV6_IPSEC_POLICY IPv4 option */
#define SOCKS_IPV6_IPSEC_POLICY_IPV6 1

/* IPV6_IPSEC_POLICY protocol level */
#define SOCKS_IPV6_IPSEC_POLICY_LVL IPPROTO_IPV6

/* IPV6_IPSEC_POLICY value */
#define SOCKS_IPV6_IPSEC_POLICY_NAME "ipv6_ipsec_policy"

/* IPV6_JOIN_ANYCAST IPv4 option */
#define SOCKS_IPV6_JOIN_ANYCAST_IPV4 0

/* IPV6_JOIN_ANYCAST IPv4 option */
#define SOCKS_IPV6_JOIN_ANYCAST_IPV6 1

/* IPV6_JOIN_ANYCAST protocol level */
#define SOCKS_IPV6_JOIN_ANYCAST_LVL IPPROTO_IPV6

/* IPV6_JOIN_ANYCAST value */
#define SOCKS_IPV6_JOIN_ANYCAST_NAME "ipv6_join_anycast"

/* IPV6_JOIN_GROUP IPv4 option */
#define SOCKS_IPV6_JOIN_GROUP_IPV4 0

/* IPV6_JOIN_GROUP IPv4 option */
#define SOCKS_IPV6_JOIN_GROUP_IPV6 1

/* IPV6_JOIN_GROUP protocol level */
#define SOCKS_IPV6_JOIN_GROUP_LVL IPPROTO_IPV6

/* IPV6_JOIN_GROUP value */
#define SOCKS_IPV6_JOIN_GROUP_NAME "ipv6_join_group"

/* IPV6_LEAVE_ANYCAST IPv4 option */
#define SOCKS_IPV6_LEAVE_ANYCAST_IPV4 0

/* IPV6_LEAVE_ANYCAST IPv4 option */
#define SOCKS_IPV6_LEAVE_ANYCAST_IPV6 1

/* IPV6_LEAVE_ANYCAST protocol level */
#define SOCKS_IPV6_LEAVE_ANYCAST_LVL IPPROTO_IPV6

/* IPV6_LEAVE_ANYCAST value */
#define SOCKS_IPV6_LEAVE_ANYCAST_NAME "ipv6_leave_anycast"

/* IPV6_LEAVE_GROUP IPv4 option */
#define SOCKS_IPV6_LEAVE_GROUP_IPV4 0

/* IPV6_LEAVE_GROUP IPv4 option */
#define SOCKS_IPV6_LEAVE_GROUP_IPV6 1

/* IPV6_LEAVE_GROUP protocol level */
#define SOCKS_IPV6_LEAVE_GROUP_LVL IPPROTO_IPV6

/* IPV6_LEAVE_GROUP value */
#define SOCKS_IPV6_LEAVE_GROUP_NAME "ipv6_leave_group"

/* IPV6_MINHOPCOUNT IPv4 option */
/* #undef SOCKS_IPV6_MINHOPCOUNT_IPV4 */

/* IPV6_MINHOPCOUNT IPv4 option */
/* #undef SOCKS_IPV6_MINHOPCOUNT_IPV6 */

/* IPV6_MINHOPCOUNT protocol level */
/* #undef SOCKS_IPV6_MINHOPCOUNT_LVL */

/* IPV6_MINHOPCOUNT value */
/* #undef SOCKS_IPV6_MINHOPCOUNT_NAME */

/* IPV6_MTU_DISCOVER IPv4 option */
#define SOCKS_IPV6_MTU_DISCOVER_IPV4 0

/* IPV6_MTU_DISCOVER IPv4 option */
#define SOCKS_IPV6_MTU_DISCOVER_IPV6 1

/* IPV6_MTU_DISCOVER protocol level */
#define SOCKS_IPV6_MTU_DISCOVER_LVL IPPROTO_IPV6

/* IPV6_MTU_DISCOVER value */
#define SOCKS_IPV6_MTU_DISCOVER_NAME "ipv6_mtu_discover"

/* IPV6_MTU IPv4 option */
#define SOCKS_IPV6_MTU_IPV4 0

/* IPV6_MTU IPv4 option */
#define SOCKS_IPV6_MTU_IPV6 1

/* IPV6_MTU protocol level */
#define SOCKS_IPV6_MTU_LVL IPPROTO_IPV6

/* IPV6_MTU value */
#define SOCKS_IPV6_MTU_NAME "ipv6_mtu"

/* IPV6_MULTICAST_HOPS IPv4 option */
#define SOCKS_IPV6_MULTICAST_HOPS_IPV4 0

/* IPV6_MULTICAST_HOPS IPv4 option */
#define SOCKS_IPV6_MULTICAST_HOPS_IPV6 1

/* IPV6_MULTICAST_HOPS protocol level */
#define SOCKS_IPV6_MULTICAST_HOPS_LVL IPPROTO_IPV6

/* IPV6_MULTICAST_HOPS value */
#define SOCKS_IPV6_MULTICAST_HOPS_NAME "ipv6_multicast_hops"

/* IPV6_MULTICAST_IF IPv4 option */
#define SOCKS_IPV6_MULTICAST_IF_IPV4 0

/* IPV6_MULTICAST_IF IPv4 option */
#define SOCKS_IPV6_MULTICAST_IF_IPV6 1

/* IPV6_MULTICAST_IF protocol level */
#define SOCKS_IPV6_MULTICAST_IF_LVL IPPROTO_IPV6

/* IPV6_MULTICAST_IF value */
#define SOCKS_IPV6_MULTICAST_IF_NAME "ipv6_multicast_if"

/* IPV6_MULTICAST_LOOP IPv4 option */
#define SOCKS_IPV6_MULTICAST_LOOP_IPV4 0

/* IPV6_MULTICAST_LOOP IPv4 option */
#define SOCKS_IPV6_MULTICAST_LOOP_IPV6 1

/* IPV6_MULTICAST_LOOP protocol level */
#define SOCKS_IPV6_MULTICAST_LOOP_LVL IPPROTO_IPV6

/* IPV6_MULTICAST_LOOP value */
#define SOCKS_IPV6_MULTICAST_LOOP_NAME "ipv6_multicast_loop"

/* IPV6_NEXTHOP IPv4 option */
#define SOCKS_IPV6_NEXTHOP_IPV4 0

/* IPV6_NEXTHOP IPv4 option */
#define SOCKS_IPV6_NEXTHOP_IPV6 1

/* IPV6_NEXTHOP protocol level */
#define SOCKS_IPV6_NEXTHOP_LVL IPPROTO_IPV6

/* IPV6_NEXTHOP value */
#define SOCKS_IPV6_NEXTHOP_NAME "ipv6_nexthop"

/* IPV6_ORIGDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_ORIGDSTADDR_IPV4 */

/* IPV6_ORIGDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_ORIGDSTADDR_IPV6 */

/* IPV6_ORIGDSTADDR protocol level */
/* #undef SOCKS_IPV6_ORIGDSTADDR_LVL */

/* IPV6_ORIGDSTADDR value */
/* #undef SOCKS_IPV6_ORIGDSTADDR_NAME */

/* IPV6_PATHMTU IPv4 option */
/* #undef SOCKS_IPV6_PATHMTU_IPV4 */

/* IPV6_PATHMTU IPv4 option */
/* #undef SOCKS_IPV6_PATHMTU_IPV6 */

/* IPV6_PATHMTU protocol level */
/* #undef SOCKS_IPV6_PATHMTU_LVL */

/* IPV6_PATHMTU value */
/* #undef SOCKS_IPV6_PATHMTU_NAME */

/* IPV6_PIPEX IPv4 option */
/* #undef SOCKS_IPV6_PIPEX_IPV4 */

/* IPV6_PIPEX IPv4 option */
/* #undef SOCKS_IPV6_PIPEX_IPV6 */

/* IPV6_PIPEX protocol level */
/* #undef SOCKS_IPV6_PIPEX_LVL */

/* IPV6_PIPEX value */
/* #undef SOCKS_IPV6_PIPEX_NAME */

/* IPV6_PKTINFO IPv4 option */
#define SOCKS_IPV6_PKTINFO_IPV4 0

/* IPV6_PKTINFO IPv4 option */
#define SOCKS_IPV6_PKTINFO_IPV6 1

/* IPV6_PKTINFO protocol level */
#define SOCKS_IPV6_PKTINFO_LVL IPPROTO_IPV6

/* IPV6_PKTINFO value */
#define SOCKS_IPV6_PKTINFO_NAME "ipv6_pktinfo"

/* IPV6_PORTRANGE IPv4 option */
/* #undef SOCKS_IPV6_PORTRANGE_IPV4 */

/* IPV6_PORTRANGE IPv4 option */
/* #undef SOCKS_IPV6_PORTRANGE_IPV6 */

/* IPV6_PORTRANGE protocol level */
/* #undef SOCKS_IPV6_PORTRANGE_LVL */

/* IPV6_PORTRANGE value */
/* #undef SOCKS_IPV6_PORTRANGE_NAME */

/* IPV6_RECVDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_RECVDSTADDR_IPV4 */

/* IPV6_RECVDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_RECVDSTADDR_IPV6 */

/* IPV6_RECVDSTADDR protocol level */
/* #undef SOCKS_IPV6_RECVDSTADDR_LVL */

/* IPV6_RECVDSTADDR value */
/* #undef SOCKS_IPV6_RECVDSTADDR_NAME */

/* IPV6_RECVDSTOPTS IPv4 option */
#define SOCKS_IPV6_RECVDSTOPTS_IPV4 0

/* IPV6_RECVDSTOPTS IPv4 option */
#define SOCKS_IPV6_RECVDSTOPTS_IPV6 1

/* IPV6_RECVDSTOPTS protocol level */
#define SOCKS_IPV6_RECVDSTOPTS_LVL IPPROTO_IPV6

/* IPV6_RECVDSTOPTS value */
#define SOCKS_IPV6_RECVDSTOPTS_NAME "ipv6_recvdstopts"

/* IPV6_RECVERR IPv4 option */
#define SOCKS_IPV6_RECVERR_IPV4 0

/* IPV6_RECVERR IPv4 option */
#define SOCKS_IPV6_RECVERR_IPV6 1

/* IPV6_RECVERR protocol level */
#define SOCKS_IPV6_RECVERR_LVL IPPROTO_IPV6

/* IPV6_RECVERR value */
#define SOCKS_IPV6_RECVERR_NAME "ipv6_recverr"

/* IPV6_RECVHOPLIMIT IPv4 option */
#define SOCKS_IPV6_RECVHOPLIMIT_IPV4 0

/* IPV6_RECVHOPLIMIT IPv4 option */
#define SOCKS_IPV6_RECVHOPLIMIT_IPV6 1

/* IPV6_RECVHOPLIMIT protocol level */
#define SOCKS_IPV6_RECVHOPLIMIT_LVL IPPROTO_IPV6

/* IPV6_RECVHOPLIMIT value */
#define SOCKS_IPV6_RECVHOPLIMIT_NAME "ipv6_recvhoplimit"

/* IPV6_RECVHOPOPTS IPv4 option */
#define SOCKS_IPV6_RECVHOPOPTS_IPV4 0

/* IPV6_RECVHOPOPTS IPv4 option */
#define SOCKS_IPV6_RECVHOPOPTS_IPV6 1

/* IPV6_RECVHOPOPTS protocol level */
#define SOCKS_IPV6_RECVHOPOPTS_LVL IPPROTO_IPV6

/* IPV6_RECVHOPOPTS value */
#define SOCKS_IPV6_RECVHOPOPTS_NAME "ipv6_recvhopopts"

/* IPV6_RECVOPTS IPv4 option */
/* #undef SOCKS_IPV6_RECVOPTS_IPV4 */

/* IPV6_RECVOPTS IPv4 option */
/* #undef SOCKS_IPV6_RECVOPTS_IPV6 */

/* IPV6_RECVOPTS protocol level */
/* #undef SOCKS_IPV6_RECVOPTS_LVL */

/* IPV6_RECVOPTS value */
/* #undef SOCKS_IPV6_RECVOPTS_NAME */

/* IPV6_RECVORIGDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_RECVORIGDSTADDR_IPV4 */

/* IPV6_RECVORIGDSTADDR IPv4 option */
/* #undef SOCKS_IPV6_RECVORIGDSTADDR_IPV6 */

/* IPV6_RECVORIGDSTADDR protocol level */
/* #undef SOCKS_IPV6_RECVORIGDSTADDR_LVL */

/* IPV6_RECVORIGDSTADDR value */
/* #undef SOCKS_IPV6_RECVORIGDSTADDR_NAME */

/* IPV6_RECVPATHMTU IPv4 option */
/* #undef SOCKS_IPV6_RECVPATHMTU_IPV4 */

/* IPV6_RECVPATHMTU IPv4 option */
/* #undef SOCKS_IPV6_RECVPATHMTU_IPV6 */

/* IPV6_RECVPATHMTU protocol level */
/* #undef SOCKS_IPV6_RECVPATHMTU_LVL */

/* IPV6_RECVPATHMTU value */
/* #undef SOCKS_IPV6_RECVPATHMTU_NAME */

/* IPV6_RECVPKTINFO IPv4 option */
#define SOCKS_IPV6_RECVPKTINFO_IPV4 0

/* IPV6_RECVPKTINFO IPv4 option */
#define SOCKS_IPV6_RECVPKTINFO_IPV6 1

/* IPV6_RECVPKTINFO protocol level */
#define SOCKS_IPV6_RECVPKTINFO_LVL IPPROTO_IPV6

/* IPV6_RECVPKTINFO value */
#define SOCKS_IPV6_RECVPKTINFO_NAME "ipv6_recvpktinfo"

/* IPV6_RECVRETOPTS IPv4 option */
/* #undef SOCKS_IPV6_RECVRETOPTS_IPV4 */

/* IPV6_RECVRETOPTS IPv4 option */
/* #undef SOCKS_IPV6_RECVRETOPTS_IPV6 */

/* IPV6_RECVRETOPTS protocol level */
/* #undef SOCKS_IPV6_RECVRETOPTS_LVL */

/* IPV6_RECVRETOPTS value */
/* #undef SOCKS_IPV6_RECVRETOPTS_NAME */

/* IPV6_RECVRTHDR IPv4 option */
#define SOCKS_IPV6_RECVRTHDR_IPV4 0

/* IPV6_RECVRTHDR IPv4 option */
#define SOCKS_IPV6_RECVRTHDR_IPV6 1

/* IPV6_RECVRTHDR protocol level */
#define SOCKS_IPV6_RECVRTHDR_LVL IPPROTO_IPV6

/* IPV6_RECVRTHDR value */
#define SOCKS_IPV6_RECVRTHDR_NAME "ipv6_recvrthdr"

/* IPV6_RECVTCLASS IPv4 option */
#define SOCKS_IPV6_RECVTCLASS_IPV4 0

/* IPV6_RECVTCLASS IPv4 option */
#define SOCKS_IPV6_RECVTCLASS_IPV6 1

/* IPV6_RECVTCLASS protocol level */
#define SOCKS_IPV6_RECVTCLASS_LVL IPPROTO_IPV6

/* IPV6_RECVTCLASS value */
#define SOCKS_IPV6_RECVTCLASS_NAME "ipv6_recvtclass"

/* IPV6_RETOPTS IPv4 option */
/* #undef SOCKS_IPV6_RETOPTS_IPV4 */

/* IPV6_RETOPTS IPv4 option */
/* #undef SOCKS_IPV6_RETOPTS_IPV6 */

/* IPV6_RETOPTS protocol level */
/* #undef SOCKS_IPV6_RETOPTS_LVL */

/* IPV6_RETOPTS value */
/* #undef SOCKS_IPV6_RETOPTS_NAME */

/* IPV6_ROUTER_ALERT IPv4 option */
#define SOCKS_IPV6_ROUTER_ALERT_IPV4 0

/* IPV6_ROUTER_ALERT IPv4 option */
#define SOCKS_IPV6_ROUTER_ALERT_IPV6 1

/* IPV6_ROUTER_ALERT protocol level */
#define SOCKS_IPV6_ROUTER_ALERT_LVL IPPROTO_IPV6

/* IPV6_ROUTER_ALERT value */
#define SOCKS_IPV6_ROUTER_ALERT_NAME "ipv6_router_alert"

/* IPV6_RTHDRDSTOPTS IPv4 option */
#define SOCKS_IPV6_RTHDRDSTOPTS_IPV4 0

/* IPV6_RTHDRDSTOPTS IPv4 option */
#define SOCKS_IPV6_RTHDRDSTOPTS_IPV6 1

/* IPV6_RTHDRDSTOPTS protocol level */
#define SOCKS_IPV6_RTHDRDSTOPTS_LVL IPPROTO_IPV6

/* IPV6_RTHDRDSTOPTS value */
#define SOCKS_IPV6_RTHDRDSTOPTS_NAME "ipv6_rthdrdstopts"

/* IPV6_RTHDR IPv4 option */
#define SOCKS_IPV6_RTHDR_IPV4 0

/* IPV6_RTHDR IPv4 option */
#define SOCKS_IPV6_RTHDR_IPV6 1

/* IPV6_RTHDR protocol level */
#define SOCKS_IPV6_RTHDR_LVL IPPROTO_IPV6

/* IPV6_RTHDR value */
#define SOCKS_IPV6_RTHDR_NAME "ipv6_rthdr"

/* IPV6_TCLASS IPv4 option */
#define SOCKS_IPV6_TCLASS_IPV4 0

/* IPV6_TCLASS IPv4 option */
#define SOCKS_IPV6_TCLASS_IPV6 1

/* IPV6_TCLASS protocol level */
#define SOCKS_IPV6_TCLASS_LVL IPPROTO_IPV6

/* IPV6_TCLASS value */
#define SOCKS_IPV6_TCLASS_NAME "ipv6_tclass"

/* IPV6_TRANSPARENT IPv4 option */
/* #undef SOCKS_IPV6_TRANSPARENT_IPV4 */

/* IPV6_TRANSPARENT IPv4 option */
/* #undef SOCKS_IPV6_TRANSPARENT_IPV6 */

/* IPV6_TRANSPARENT protocol level */
/* #undef SOCKS_IPV6_TRANSPARENT_LVL */

/* IPV6_TRANSPARENT value */
/* #undef SOCKS_IPV6_TRANSPARENT_NAME */

/* IPV6_UNICAST_HOPS IPv4 option */
#define SOCKS_IPV6_UNICAST_HOPS_IPV4 0

/* IPV6_UNICAST_HOPS IPv4 option */
#define SOCKS_IPV6_UNICAST_HOPS_IPV6 1

/* IPV6_UNICAST_HOPS protocol level */
#define SOCKS_IPV6_UNICAST_HOPS_LVL IPPROTO_IPV6

/* IPV6_UNICAST_HOPS value */
#define SOCKS_IPV6_UNICAST_HOPS_NAME "ipv6_unicast_hops"

/* IPV6_USE_MIN_MTU IPv4 option */
/* #undef SOCKS_IPV6_USE_MIN_MTU_IPV4 */

/* IPV6_USE_MIN_MTU IPv4 option */
/* #undef SOCKS_IPV6_USE_MIN_MTU_IPV6 */

/* IPV6_USE_MIN_MTU protocol level */
/* #undef SOCKS_IPV6_USE_MIN_MTU_LVL */

/* IPV6_USE_MIN_MTU value */
/* #undef SOCKS_IPV6_USE_MIN_MTU_NAME */

/* IPV6_V6ONLY IPv4 option */
#define SOCKS_IPV6_V6ONLY_IPV4 0

/* IPV6_V6ONLY IPv4 option */
#define SOCKS_IPV6_V6ONLY_IPV6 1

/* IPV6_V6ONLY protocol level */
#define SOCKS_IPV6_V6ONLY_LVL IPPROTO_IPV6

/* IPV6_V6ONLY value */
#define SOCKS_IPV6_V6ONLY_NAME "ipv6_v6only"

/* IPV6_XFRM_POLICY IPv4 option */
#define SOCKS_IPV6_XFRM_POLICY_IPV4 0

/* IPV6_XFRM_POLICY IPv4 option */
#define SOCKS_IPV6_XFRM_POLICY_IPV6 1

/* IPV6_XFRM_POLICY protocol level */
#define SOCKS_IPV6_XFRM_POLICY_LVL IPPROTO_IPV6

/* IPV6_XFRM_POLICY value */
#define SOCKS_IPV6_XFRM_POLICY_NAME "ipv6_xfrm_policy"

/* IP_AUTH_LEVEL IPv4 option */
/* #undef SOCKS_IP_AUTH_LEVEL_IPV4 */

/* IP_AUTH_LEVEL IPv4 option */
/* #undef SOCKS_IP_AUTH_LEVEL_IPV6 */

/* IP_AUTH_LEVEL protocol level */
/* #undef SOCKS_IP_AUTH_LEVEL_LVL */

/* IP_AUTH_LEVEL value */
/* #undef SOCKS_IP_AUTH_LEVEL_NAME */

/* IP_DONTFRAG IPv4 option */
/* #undef SOCKS_IP_DONTFRAG_IPV4 */

/* IP_DONTFRAG IPv4 option */
/* #undef SOCKS_IP_DONTFRAG_IPV6 */

/* IP_DONTFRAG protocol level */
/* #undef SOCKS_IP_DONTFRAG_LVL */

/* IP_DONTFRAG value */
/* #undef SOCKS_IP_DONTFRAG_NAME */

/* IP_ESP_NETWORK_LEVEL IPv4 option */
/* #undef SOCKS_IP_ESP_NETWORK_LEVEL_IPV4 */

/* IP_ESP_NETWORK_LEVEL IPv4 option */
/* #undef SOCKS_IP_ESP_NETWORK_LEVEL_IPV6 */

/* IP_ESP_NETWORK_LEVEL protocol level */
/* #undef SOCKS_IP_ESP_NETWORK_LEVEL_LVL */

/* IP_ESP_NETWORK_LEVEL value */
/* #undef SOCKS_IP_ESP_NETWORK_LEVEL_NAME */

/* IP_ESP_TRANS_LEVEL IPv4 option */
/* #undef SOCKS_IP_ESP_TRANS_LEVEL_IPV4 */

/* IP_ESP_TRANS_LEVEL IPv4 option */
/* #undef SOCKS_IP_ESP_TRANS_LEVEL_IPV6 */

/* IP_ESP_TRANS_LEVEL protocol level */
/* #undef SOCKS_IP_ESP_TRANS_LEVEL_LVL */

/* IP_ESP_TRANS_LEVEL value */
/* #undef SOCKS_IP_ESP_TRANS_LEVEL_NAME */

/* IP_FREEBIND IPv4 option */
#define SOCKS_IP_FREEBIND_IPV4 1

/* IP_FREEBIND IPv4 option */
#define SOCKS_IP_FREEBIND_IPV6 0

/* IP_FREEBIND protocol level */
#define SOCKS_IP_FREEBIND_LVL IPPROTO_IP

/* IP_FREEBIND value */
#define SOCKS_IP_FREEBIND_NAME "ip_freebind"

/* IP_HDRINCL IPv4 option */
#define SOCKS_IP_HDRINCL_IPV4 1

/* IP_HDRINCL IPv4 option */
#define SOCKS_IP_HDRINCL_IPV6 0

/* IP_HDRINCL protocol level */
#define SOCKS_IP_HDRINCL_LVL IPPROTO_IP

/* IP_HDRINCL value */
#define SOCKS_IP_HDRINCL_NAME "ip_hdrincl"

/* IP_IPCOMP_LEVEL IPv4 option */
/* #undef SOCKS_IP_IPCOMP_LEVEL_IPV4 */

/* IP_IPCOMP_LEVEL IPv4 option */
/* #undef SOCKS_IP_IPCOMP_LEVEL_IPV6 */

/* IP_IPCOMP_LEVEL protocol level */
/* #undef SOCKS_IP_IPCOMP_LEVEL_LVL */

/* IP_IPCOMP_LEVEL value */
/* #undef SOCKS_IP_IPCOMP_LEVEL_NAME */

/* IP_MINTTL IPv4 option */
#define SOCKS_IP_MINTTL_IPV4 1

/* IP_MINTTL IPv4 option */
#define SOCKS_IP_MINTTL_IPV6 0

/* IP_MINTTL protocol level */
#define SOCKS_IP_MINTTL_LVL IPPROTO_IP

/* IP_MINTTL value */
#define SOCKS_IP_MINTTL_NAME "ip_minttl"

/* IP_MTU_DISCOVER IPv4 option */
#define SOCKS_IP_MTU_DISCOVER_IPV4 1

/* IP_MTU_DISCOVER IPv4 option */
#define SOCKS_IP_MTU_DISCOVER_IPV6 0

/* IP_MTU_DISCOVER protocol level */
#define SOCKS_IP_MTU_DISCOVER_LVL IPPROTO_IP

/* IP_MTU_DISCOVER value */
#define SOCKS_IP_MTU_DISCOVER_NAME "ip_mtu_discover"

/* IP_MULTICAST_IF IPv4 option */
#define SOCKS_IP_MULTICAST_IF_IPV4 1

/* IP_MULTICAST_IF IPv4 option */
#define SOCKS_IP_MULTICAST_IF_IPV6 0

/* IP_MULTICAST_IF protocol level */
#define SOCKS_IP_MULTICAST_IF_LVL IPPROTO_IP

/* IP_MULTICAST_IF value */
#define SOCKS_IP_MULTICAST_IF_NAME "ip_multicast_if"

/* IP_MULTICAST_LOOP IPv4 option */
#define SOCKS_IP_MULTICAST_LOOP_IPV4 1

/* IP_MULTICAST_LOOP IPv4 option */
#define SOCKS_IP_MULTICAST_LOOP_IPV6 0

/* IP_MULTICAST_LOOP protocol level */
#define SOCKS_IP_MULTICAST_LOOP_LVL IPPROTO_IP

/* IP_MULTICAST_LOOP value */
#define SOCKS_IP_MULTICAST_LOOP_NAME "ip_multicast_loop"

/* IP_MULTICAST_TTL IPv4 option */
#define SOCKS_IP_MULTICAST_TTL_IPV4 1

/* IP_MULTICAST_TTL IPv4 option */
#define SOCKS_IP_MULTICAST_TTL_IPV6 0

/* IP_MULTICAST_TTL protocol level */
#define SOCKS_IP_MULTICAST_TTL_LVL IPPROTO_IP

/* IP_MULTICAST_TTL value */
#define SOCKS_IP_MULTICAST_TTL_NAME "ip_multicast_ttl"

/* IP_OPTIONS IPv4 option */
#define SOCKS_IP_OPTIONS_IPV4 1

/* IP_OPTIONS IPv4 option */
#define SOCKS_IP_OPTIONS_IPV6 0

/* IP_OPTIONS protocol level */
#define SOCKS_IP_OPTIONS_LVL IPPROTO_IP

/* IP_OPTIONS value */
#define SOCKS_IP_OPTIONS_NAME "ip_options"

/* IP_PORTRANGE_DEFAULT value */
/* #undef SOCKS_IP_PORTRANGE_DEFAULT_SYMNAME */

/* IP_PORTRANGE_HIGH value */
/* #undef SOCKS_IP_PORTRANGE_HIGH_SYMNAME */

/* IP_PORTRANGE IPv4 option */
/* #undef SOCKS_IP_PORTRANGE_IPV4 */

/* IP_PORTRANGE IPv4 option */
/* #undef SOCKS_IP_PORTRANGE_IPV6 */

/* IP_PORTRANGE_LOW value */
/* #undef SOCKS_IP_PORTRANGE_LOW_SYMNAME */

/* IP_PORTRANGE protocol level */
/* #undef SOCKS_IP_PORTRANGE_LVL */

/* IP_PORTRANGE value */
/* #undef SOCKS_IP_PORTRANGE_NAME */

/* IP_RECVDSTADDR IPv4 option */
/* #undef SOCKS_IP_RECVDSTADDR_IPV4 */

/* IP_RECVDSTADDR IPv4 option */
/* #undef SOCKS_IP_RECVDSTADDR_IPV6 */

/* IP_RECVDSTADDR protocol level */
/* #undef SOCKS_IP_RECVDSTADDR_LVL */

/* IP_RECVDSTADDR value */
/* #undef SOCKS_IP_RECVDSTADDR_NAME */

/* IP_RECVIF IPv4 option */
/* #undef SOCKS_IP_RECVIF_IPV4 */

/* IP_RECVIF IPv4 option */
/* #undef SOCKS_IP_RECVIF_IPV6 */

/* IP_RECVIF protocol level */
/* #undef SOCKS_IP_RECVIF_LVL */

/* IP_RECVIF value */
/* #undef SOCKS_IP_RECVIF_NAME */

/* IP_RECVTOS IPv4 option */
#define SOCKS_IP_RECVTOS_IPV4 1

/* IP_RECVTOS IPv4 option */
#define SOCKS_IP_RECVTOS_IPV6 0

/* IP_RECVTOS protocol level */
#define SOCKS_IP_RECVTOS_LVL IPPROTO_IP

/* IP_RECVTOS value */
#define SOCKS_IP_RECVTOS_NAME "ip_recvtos"

/* IP_RECVTTL IPv4 option */
#define SOCKS_IP_RECVTTL_IPV4 1

/* IP_RECVTTL IPv4 option */
#define SOCKS_IP_RECVTTL_IPV6 0

/* IP_RECVTTL protocol level */
#define SOCKS_IP_RECVTTL_LVL IPPROTO_IP

/* IP_RECVTTL value */
#define SOCKS_IP_RECVTTL_NAME "ip_recvttl"

/* IP_TOS subfield */
#define SOCKS_IP_TOS_DSCP_NAME "ip_tos.dscp"

/* IP_TOS IPv4 option */
#define SOCKS_IP_TOS_IPV4 1

/* IP_TOS IPv4 option */
#define SOCKS_IP_TOS_IPV6 0

/* IP_TOS protocol level */
#define SOCKS_IP_TOS_LVL IPPROTO_IP

/* IP_TOS value */
#define SOCKS_IP_TOS_NAME "ip_tos"

/* IP_TOS subfield */
#define SOCKS_IP_TOS_PREC_NAME "ip_tos.prec"

/* IP_TOS subfield */
#define SOCKS_IP_TOS_TOS_NAME "ip_tos.tos"

/* IP_TTL IPv4 option */
#define SOCKS_IP_TTL_IPV4 1

/* IP_TTL IPv4 option */
#define SOCKS_IP_TTL_IPV6 0

/* IP_TTL protocol level */
#define SOCKS_IP_TTL_LVL IPPROTO_IP

/* IP_TTL value */
#define SOCKS_IP_TTL_NAME "ip_ttl"

/* Guess at max number of valid signals */
#define SOCKS_NSIG 128

/* SO_BINDANY IPv4 option */
/* #undef SOCKS_SO_BINDANY_IPV4 */

/* SO_BINDANY IPv4 option */
/* #undef SOCKS_SO_BINDANY_IPV6 */

/* SO_BINDANY protocol level */
/* #undef SOCKS_SO_BINDANY_LVL */

/* SO_BINDANY value */
/* #undef SOCKS_SO_BINDANY_NAME */

/* SO_BROADCAST IPv4 option */
#define SOCKS_SO_BROADCAST_IPV4 1

/* SO_BROADCAST IPv4 option */
#define SOCKS_SO_BROADCAST_IPV6 1

/* SO_BROADCAST protocol level */
#define SOCKS_SO_BROADCAST_LVL SOL_SOCKET

/* SO_BROADCAST value */
#define SOCKS_SO_BROADCAST_NAME "so_broadcast"

/* SO_DEBUG IPv4 option */
#define SOCKS_SO_DEBUG_IPV4 1

/* SO_DEBUG IPv4 option */
#define SOCKS_SO_DEBUG_IPV6 1

/* SO_DEBUG protocol level */
#define SOCKS_SO_DEBUG_LVL SOL_SOCKET

/* SO_DEBUG value */
#define SOCKS_SO_DEBUG_NAME "so_debug"

/* SO_DONTROUTE IPv4 option */
#define SOCKS_SO_DONTROUTE_IPV4 1

/* SO_DONTROUTE IPv4 option */
#define SOCKS_SO_DONTROUTE_IPV6 1

/* SO_DONTROUTE protocol level */
#define SOCKS_SO_DONTROUTE_LVL SOL_SOCKET

/* SO_DONTROUTE value */
#define SOCKS_SO_DONTROUTE_NAME "so_dontroute"

/* SO_JUMBO IPv4 option */
/* #undef SOCKS_SO_JUMBO_IPV4 */

/* SO_JUMBO IPv4 option */
/* #undef SOCKS_SO_JUMBO_IPV6 */

/* SO_JUMBO protocol level */
/* #undef SOCKS_SO_JUMBO_LVL */

/* SO_JUMBO value */
/* #undef SOCKS_SO_JUMBO_NAME */

/* SO_KEEPALIVE IPv4 option */
#define SOCKS_SO_KEEPALIVE_IPV4 1

/* SO_KEEPALIVE IPv4 option */
#define SOCKS_SO_KEEPALIVE_IPV6 1

/* SO_KEEPALIVE protocol level */
#define SOCKS_SO_KEEPALIVE_LVL SOL_SOCKET

/* SO_KEEPALIVE value */
#define SOCKS_SO_KEEPALIVE_NAME "so_keepalive"

/* SO_LINGER IPv4 option */
#define SOCKS_SO_LINGER_IPV4 1

/* SO_LINGER IPv4 option */
#define SOCKS_SO_LINGER_IPV6 1

/* SO_LINGER protocol level */
#define SOCKS_SO_LINGER_LVL SOL_SOCKET

/* SO_LINGER value */
#define SOCKS_SO_LINGER_NAME "so_linger"

/* SO_OOBINLINE IPv4 option */
#define SOCKS_SO_OOBINLINE_IPV4 1

/* SO_OOBINLINE IPv4 option */
#define SOCKS_SO_OOBINLINE_IPV6 1

/* SO_OOBINLINE protocol level */
#define SOCKS_SO_OOBINLINE_LVL SOL_SOCKET

/* SO_OOBINLINE value */
#define SOCKS_SO_OOBINLINE_NAME "so_oobinline"

/* SO_PRIORITY IPv4 option */
#define SOCKS_SO_PRIORITY_IPV4 1

/* SO_PRIORITY IPv4 option */
#define SOCKS_SO_PRIORITY_IPV6 1

/* SO_PRIORITY protocol level */
#define SOCKS_SO_PRIORITY_LVL SOL_SOCKET

/* SO_PRIORITY value */
#define SOCKS_SO_PRIORITY_NAME "so_priority"

/* SO_RCVBUFFORCE IPv4 option */
#define SOCKS_SO_RCVBUFFORCE_IPV4 1

/* SO_RCVBUFFORCE IPv4 option */
#define SOCKS_SO_RCVBUFFORCE_IPV6 1

/* SO_RCVBUFFORCE protocol level */
#define SOCKS_SO_RCVBUFFORCE_LVL SOL_SOCKET

/* SO_RCVBUFFORCE value */
#define SOCKS_SO_RCVBUFFORCE_NAME "so_rcvbufforce"

/* SO_RCVBUF IPv4 option */
#define SOCKS_SO_RCVBUF_IPV4 1

/* SO_RCVBUF IPv4 option */
#define SOCKS_SO_RCVBUF_IPV6 1

/* SO_RCVBUF protocol level */
#define SOCKS_SO_RCVBUF_LVL SOL_SOCKET

/* SO_RCVBUF value */
#define SOCKS_SO_RCVBUF_NAME "so_rcvbuf"

/* SO_RCVLOWAT IPv4 option */
#define SOCKS_SO_RCVLOWAT_IPV4 1

/* SO_RCVLOWAT IPv4 option */
#define SOCKS_SO_RCVLOWAT_IPV6 1

/* SO_RCVLOWAT protocol level */
#define SOCKS_SO_RCVLOWAT_LVL SOL_SOCKET

/* SO_RCVLOWAT value */
#define SOCKS_SO_RCVLOWAT_NAME "so_rcvlowat"

/* SO_RCVTIMEO IPv4 option */
#define SOCKS_SO_RCVTIMEO_IPV4 1

/* SO_RCVTIMEO IPv4 option */
#define SOCKS_SO_RCVTIMEO_IPV6 1

/* SO_RCVTIMEO protocol level */
#define SOCKS_SO_RCVTIMEO_LVL SOL_SOCKET

/* SO_RCVTIMEO value */
#define SOCKS_SO_RCVTIMEO_NAME "so_rcvtimeo"

/* SO_REUSEADDR IPv4 option */
#define SOCKS_SO_REUSEADDR_IPV4 1

/* SO_REUSEADDR IPv4 option */
#define SOCKS_SO_REUSEADDR_IPV6 1

/* SO_REUSEADDR protocol level */
#define SOCKS_SO_REUSEADDR_LVL SOL_SOCKET

/* SO_REUSEADDR value */
#define SOCKS_SO_REUSEADDR_NAME "so_reuseaddr"

/* SO_REUSEPORT IPv4 option */
/* #undef SOCKS_SO_REUSEPORT_IPV4 */

/* SO_REUSEPORT IPv4 option */
/* #undef SOCKS_SO_REUSEPORT_IPV6 */

/* SO_REUSEPORT protocol level */
/* #undef SOCKS_SO_REUSEPORT_LVL */

/* SO_REUSEPORT value */
/* #undef SOCKS_SO_REUSEPORT_NAME */

/* SO_SNDBUFFORCE IPv4 option */
#define SOCKS_SO_SNDBUFFORCE_IPV4 1

/* SO_SNDBUFFORCE IPv4 option */
#define SOCKS_SO_SNDBUFFORCE_IPV6 1

/* SO_SNDBUFFORCE protocol level */
#define SOCKS_SO_SNDBUFFORCE_LVL SOL_SOCKET

/* SO_SNDBUFFORCE value */
#define SOCKS_SO_SNDBUFFORCE_NAME "so_sndbufforce"

/* SO_SNDBUF IPv4 option */
#define SOCKS_SO_SNDBUF_IPV4 1

/* SO_SNDBUF IPv4 option */
#define SOCKS_SO_SNDBUF_IPV6 1

/* SO_SNDBUF protocol level */
#define SOCKS_SO_SNDBUF_LVL SOL_SOCKET

/* SO_SNDBUF value */
#define SOCKS_SO_SNDBUF_NAME "so_sndbuf"

/* SO_SNDLOWAT IPv4 option */
#define SOCKS_SO_SNDLOWAT_IPV4 1

/* SO_SNDLOWAT IPv4 option */
#define SOCKS_SO_SNDLOWAT_IPV6 1

/* SO_SNDLOWAT protocol level */
#define SOCKS_SO_SNDLOWAT_LVL SOL_SOCKET

/* SO_SNDLOWAT value */
#define SOCKS_SO_SNDLOWAT_NAME "so_sndlowat"

/* SO_SNDTIMEO IPv4 option */
#define SOCKS_SO_SNDTIMEO_IPV4 1

/* SO_SNDTIMEO IPv4 option */
#define SOCKS_SO_SNDTIMEO_IPV6 1

/* SO_SNDTIMEO protocol level */
#define SOCKS_SO_SNDTIMEO_LVL SOL_SOCKET

/* SO_SNDTIMEO value */
#define SOCKS_SO_SNDTIMEO_NAME "so_sndtimeo"

/* SO_TIMESTAMP IPv4 option */
#define SOCKS_SO_TIMESTAMP_IPV4 1

/* SO_TIMESTAMP IPv4 option */
#define SOCKS_SO_TIMESTAMP_IPV6 1

/* SO_TIMESTAMP protocol level */
#define SOCKS_SO_TIMESTAMP_LVL SOL_SOCKET

/* SO_TIMESTAMP value */
#define SOCKS_SO_TIMESTAMP_NAME "so_timestamp"

/* SO_USELOOPBACK IPv4 option */
/* #undef SOCKS_SO_USELOOPBACK_IPV4 */

/* SO_USELOOPBACK IPv4 option */
/* #undef SOCKS_SO_USELOOPBACK_IPV6 */

/* SO_USELOOPBACK protocol level */
/* #undef SOCKS_SO_USELOOPBACK_LVL */

/* SO_USELOOPBACK value */
/* #undef SOCKS_SO_USELOOPBACK_NAME */

/* TCP_CORK IPv4 option */
#define SOCKS_TCP_CORK_IPV4 1

/* TCP_CORK IPv4 option */
#define SOCKS_TCP_CORK_IPV6 1

/* TCP_CORK protocol level */
#define SOCKS_TCP_CORK_LVL IPPROTO_TCP

/* TCP_CORK value */
#define SOCKS_TCP_CORK_NAME "tcp_cork"

/* TCP_CWND IPv4 option */
/* #undef SOCKS_TCP_CWND_IPV4 */

/* TCP_CWND IPv4 option */
/* #undef SOCKS_TCP_CWND_IPV6 */

/* TCP_CWND protocol level */
/* #undef SOCKS_TCP_CWND_LVL */

/* TCP_CWND value */
/* #undef SOCKS_TCP_CWND_NAME */

/* TCP_INIT_CWND IPv4 option */
/* #undef SOCKS_TCP_INIT_CWND_IPV4 */

/* TCP_INIT_CWND IPv4 option */
/* #undef SOCKS_TCP_INIT_CWND_IPV6 */

/* TCP_INIT_CWND protocol level */
/* #undef SOCKS_TCP_INIT_CWND_LVL */

/* TCP_INIT_CWND value */
/* #undef SOCKS_TCP_INIT_CWND_NAME */

/* TCP_IPA IPv4 option */
/* #undef SOCKS_TCP_IPA_IPV4 */

/* TCP_IPA IPv4 option */
/* #undef SOCKS_TCP_IPA_IPV6 */

/* TCP_IPA protocol level */
/* #undef SOCKS_TCP_IPA_LVL */

/* TCP_IPA value */
/* #undef SOCKS_TCP_IPA_NAME */

/* TCP_KEEPCNT IPv4 option */
#define SOCKS_TCP_KEEPCNT_IPV4 1

/* TCP_KEEPCNT IPv4 option */
#define SOCKS_TCP_KEEPCNT_IPV6 1

/* TCP_KEEPCNT protocol level */
#define SOCKS_TCP_KEEPCNT_LVL IPPROTO_TCP

/* TCP_KEEPCNT value */
#define SOCKS_TCP_KEEPCNT_NAME "tcp_keepcnt"

/* TCP_KEEPIDLE IPv4 option */
#define SOCKS_TCP_KEEPIDLE_IPV4 1

/* TCP_KEEPIDLE IPv4 option */
#define SOCKS_TCP_KEEPIDLE_IPV6 1

/* TCP_KEEPIDLE protocol level */
#define SOCKS_TCP_KEEPIDLE_LVL IPPROTO_TCP

/* TCP_KEEPIDLE value */
#define SOCKS_TCP_KEEPIDLE_NAME "tcp_keepidle"

/* TCP_KEEPINTVL IPv4 option */
#define SOCKS_TCP_KEEPINTVL_IPV4 1

/* TCP_KEEPINTVL IPv4 option */
#define SOCKS_TCP_KEEPINTVL_IPV6 1

/* TCP_KEEPINTVL protocol level */
#define SOCKS_TCP_KEEPINTVL_LVL IPPROTO_TCP

/* TCP_KEEPINTVL value */
#define SOCKS_TCP_KEEPINTVL_NAME "tcp_keepintvl"

/* TCP_LINGER2 IPv4 option */
#define SOCKS_TCP_LINGER2_IPV4 1

/* TCP_LINGER2 IPv4 option */
#define SOCKS_TCP_LINGER2_IPV6 1

/* TCP_LINGER2 protocol level */
#define SOCKS_TCP_LINGER2_LVL IPPROTO_TCP

/* TCP_LINGER2 value */
#define SOCKS_TCP_LINGER2_NAME "tcp_linger2"

/* TCP_MAXRT IPv4 option */
/* #undef SOCKS_TCP_MAXRT_IPV4 */

/* TCP_MAXRT IPv4 option */
/* #undef SOCKS_TCP_MAXRT_IPV6 */

/* TCP_MAXRT protocol level */
/* #undef SOCKS_TCP_MAXRT_LVL */

/* TCP_MAXRT value */
/* #undef SOCKS_TCP_MAXRT_NAME */

/* TCP_MAXSEG IPv4 option */
#define SOCKS_TCP_MAXSEG_IPV4 1

/* TCP_MAXSEG IPv4 option */
#define SOCKS_TCP_MAXSEG_IPV6 1

/* TCP_MAXSEG protocol level */
#define SOCKS_TCP_MAXSEG_LVL IPPROTO_TCP

/* TCP_MAXSEG value */
#define SOCKS_TCP_MAXSEG_NAME "tcp_maxseg"

/* TCP_MD5SIG IPv4 option */
#define SOCKS_TCP_MD5SIG_IPV4 1

/* TCP_MD5SIG IPv4 option */
#define SOCKS_TCP_MD5SIG_IPV6 1

/* TCP_MD5SIG protocol level */
#define SOCKS_TCP_MD5SIG_LVL IPPROTO_TCP

/* TCP_MD5SIG value */
#define SOCKS_TCP_MD5SIG_NAME "tcp_md5sig"

/* TCP_NODELAY IPv4 option */
#define SOCKS_TCP_NODELAY_IPV4 1

/* TCP_NODELAY IPv4 option */
#define SOCKS_TCP_NODELAY_IPV6 1

/* TCP_NODELAY protocol level */
#define SOCKS_TCP_NODELAY_LVL IPPROTO_TCP

/* TCP_NODELAY value */
#define SOCKS_TCP_NODELAY_NAME "tcp_nodelay"

/* TCP_NOOPT IPv4 option */
/* #undef SOCKS_TCP_NOOPT_IPV4 */

/* TCP_NOOPT IPv4 option */
/* #undef SOCKS_TCP_NOOPT_IPV6 */

/* TCP_NOOPT protocol level */
/* #undef SOCKS_TCP_NOOPT_LVL */

/* TCP_NOOPT value */
/* #undef SOCKS_TCP_NOOPT_NAME */

/* TCP_NOPUSH IPv4 option */
/* #undef SOCKS_TCP_NOPUSH_IPV4 */

/* TCP_NOPUSH IPv4 option */
/* #undef SOCKS_TCP_NOPUSH_IPV6 */

/* TCP_NOPUSH protocol level */
/* #undef SOCKS_TCP_NOPUSH_LVL */

/* TCP_NOPUSH value */
/* #undef SOCKS_TCP_NOPUSH_NAME */

/* TCP_SACK_ENABLE IPv4 option */
/* #undef SOCKS_TCP_SACK_ENABLE_IPV4 */

/* TCP_SACK_ENABLE IPv4 option */
/* #undef SOCKS_TCP_SACK_ENABLE_IPV6 */

/* TCP_SACK_ENABLE protocol level */
/* #undef SOCKS_TCP_SACK_ENABLE_LVL */

/* TCP_SACK_ENABLE value */
/* #undef SOCKS_TCP_SACK_ENABLE_NAME */

/* TCP_STDURG IPv4 option */
/* #undef SOCKS_TCP_STDURG_IPV4 */

/* TCP_STDURG IPv4 option */
/* #undef SOCKS_TCP_STDURG_IPV6 */

/* TCP_STDURG protocol level */
/* #undef SOCKS_TCP_STDURG_LVL */

/* TCP_STDURG value */
/* #undef SOCKS_TCP_STDURG_NAME */

/* TCP_SYNCNT IPv4 option */
#define SOCKS_TCP_SYNCNT_IPV4 1

/* TCP_SYNCNT IPv4 option */
#define SOCKS_TCP_SYNCNT_IPV6 1

/* TCP_SYNCNT protocol level */
#define SOCKS_TCP_SYNCNT_LVL IPPROTO_TCP

/* TCP_SYNCNT value */
#define SOCKS_TCP_SYNCNT_NAME "tcp_syncnt"

/* TCP_WINDOW_CLAMP IPv4 option */
#define SOCKS_TCP_WINDOW_CLAMP_IPV4 1

/* TCP_WINDOW_CLAMP IPv4 option */
#define SOCKS_TCP_WINDOW_CLAMP_IPV6 1

/* TCP_WINDOW_CLAMP protocol level */
#define SOCKS_TCP_WINDOW_CLAMP_LVL IPPROTO_TCP

/* TCP_WINDOW_CLAMP value */
#define SOCKS_TCP_WINDOW_CLAMP_NAME "tcp_window_clamp"

/* UDP_CORK IPv4 option */
#define SOCKS_UDP_CORK_IPV4 1

/* UDP_CORK IPv4 option */
#define SOCKS_UDP_CORK_IPV6 1

/* UDP_CORK protocol level */
#define SOCKS_UDP_CORK_LVL IPPROTO_UDP

/* UDP_CORK value */
#define SOCKS_UDP_CORK_NAME "udp_cork"

/* setproctitle replacement type */
#define SPT_TYPE SPT_REUSEARGV

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Number of unique errno numbers */
#define UNIQUE_ERRNO_VALUES 119

/* Number of unique getaddrinfo() error numbers */
#define UNIQUE_GAIERR_VALUES 10

/* Version number of package */
#define VERSION "1.4.0"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* contents from old AC_AIX test */
/* #undef _ALL_SOURCE */

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* bzero replacement */
/* #undef bzero */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* use getpassphrase */
/* #undef getpass */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* gss_nt_service_name replacement */
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* resolver options type */
#define res_options_type_t u_long

/* sa_len type */
#define sa_len_type socklen_t

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* platform workaround */
/* #undef socklen_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */


#include "redefac.h"

