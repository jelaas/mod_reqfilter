#ifndef RH_H
#define RH_H

#define RECSTART "@£$1"
#define RECSTOP "@£$0"
#define ENDOFLINE "@£$2"

#define RECSIZE 2048
#define NRECORDS 8

#ifndef RF_INTERNAL
extern char recording[NRECORDS][RECSIZE];
char regex_group[NRECORDS][RECSIZE];
#endif
/*
 * Query hostname DNS-format.
 * Example: host("www.aaa.bb")
 */
int host(const char *hostname);

/*
 * Return true if the path component of the URI equals 'path'.
 */
int path(const char *path);

/*
 * Return true if the path component of the URI begins with 'path'.
 */
int path_prefix(const char *path);
  
/*
 * Path matching.
 * If arg matches the search (and path position) advances to the next arg.
 * If an arg does not match the next arg is tried against the same position in path.
 * The last arg MUST match.
 * If the last arg matches the function returns true.
 * If arg is RECSTART then everything that matches in path is stored in the global variable recording[n], until RECSTOP.
 *  The index [n] is increased with every encounter of RECSTART.
 *
 * Example: path_match("/", "dir/", RECSTART, "favicon.ico", RECSTOP))
 */
int _path_match( const char *noop, ...);
#define path_match(A...) _path_match(NULL, ##A, NULL)

/*
 * Generic regexp
 * Matching groups are store din regex_group[]
 */
int regex(const char *buffer, const char *expr);

/*
 * Regexp match of path component of the URI.
 */
int path_regex(const char *expr);

/*
 * The hostname to send for a proxy-request.
 */
int proxy_host(const char *hostname);

/*
 * Reverse proxy translation
 */
int proxy_reverse(const char *real, const char *fake);

/*
 * Proxy request
 */
int _proxy_to(const char *URI, ...);
#define proxy_to(URI, A...) _proxy_to(URI,##A, NULL)

/*
 * We are done processing and return to the request handling.
 */
void done();

void debug();

#endif