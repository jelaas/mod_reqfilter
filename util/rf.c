#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <pcre.h>

#define RF_INTERNAL
#include "rf.h"

char recording[NRECORDS][RECSIZE];
char regex_group[NRECORDS][RECSIZE];

static int _rf_debug;

/*
 * Query hostname DNS-format.
 * Example: host("www.aaa.bb")
 */
int host(const char *hostname)
{
	char *u = getenv("IN::Host");
	if(!u) {
		u = getenv("IN__Host");
		if(!u) return 0;
	}
	if(_rf_debug) fprintf(stderr, "host() strcmp(\"%s\", \"%s\") == %d\n", hostname, u, strcmp(hostname, u));
	return strcmp(hostname, u)==0;
}

/*
 * Return true if the path component of the URI equals 'path'.
 */
int path(const char *path)
{
	char *u = getenv("DOCUMENT_URI");
	if(!u) return 0;
	if(_rf_debug) fprintf(stderr, "path() strcmp(\"%s\", \"%s\") == %d\n", path, u, strcmp(path, u));
	return strcmp(path, u)==0;
}

/*
 * Return true if the path component of the URI begins with 'path'.
 */
int path_prefix(const char *path)
{
	char *u = getenv("DOCUMENT_URI");
	if(!u) return 0;
	if(_rf_debug) fprintf(stderr, "path_prefix() strncmp(\"%s\", \"%s\", %d) == %d\n", path, u, strlen(path), strncmp(path, u, strlen(path)));
        return strncmp(path, u, strlen(path))==0;
}

/*
 * Path matching.
 * If arg matches the search (and path position) advances to the next arg.
 * If an arg does not match the next arg is tried against the same position in path.
 * The last arg MUST match.
 * If the last arg matches the function returns true.
 * If arg is RECSTART then everything that matches in path is stored in the global variable recording[n], until RECSTOP.
 *  The index [n] is increased with every encounter of RECSTART.
 *
 * Example: path_match("/", "dir/", RECSTART, "favicon.ico", RECSTOP, ENDOFLINE))
 */
int _path_match( const char *noop, ...)
{
	const char *pe, *nextpe, *path;
	int last = 0;
	int rec = -1;
	int rec_on = 0;
	int cmpstatus = 1;
	va_list ap;
	
	path = getenv("DOCUMENT_URI");
	if(!path) return 0;

	va_start(ap, noop);
	
	pe = va_arg(ap, char *);

	while(pe) {
		if(strcmp(pe, RECSTART)==0) {
			if((rec+1) < NRECORDS) {
				rec++;
				if(_rf_debug) fprintf(stderr, "path_match() RECSTART %d\n", rec);
				rec_on=1;
				recording[0][0] = 0;
			} else {
				if(_rf_debug) fprintf(stderr, "path_match() RECSTART declined\n");
			}
			pe = va_arg(ap, char *);
		}
		if(strcmp(pe, RECSTOP)==0) {
			rec_on=0;
			if(_rf_debug) fprintf(stderr, "path_match() RECSTOP %d\n", rec);
			if(_rf_debug) fprintf(stderr, "path_match() recording[%d] = \"%s\"\n", rec, recording[rec]);
			pe = va_arg(ap, char *);
			if(!pe) {
				va_end(ap);
				return cmpstatus;				
			}
		}
		nextpe = va_arg(ap, char *);
		if(nextpe == NULL)
			last = 1;
		if(strcmp(pe, ENDOFLINE)==0) {
			if(*path)
				cmpstatus = 0;
			else
				cmpstatus = 1;
		} else {
			if(_rf_debug) fprintf(stderr, "path_match() strncmp(\"%s\", \"%s\", %d) == %d\n",
					      path, pe, strlen(pe), strncmp(path, pe, strlen(pe)));
			if(strncmp(path, pe, strlen(pe))==0) {
				cmpstatus=1;
				path += strlen(pe);
				if(rec_on) {
					if(strlen(pe) + strlen(recording[rec]) < RECSIZE)
						strcat(recording[rec], pe);
					else
						strncat(recording[rec], pe, RECSIZE - strlen(recording[rec]) - 1);
					if(last) {
						if(strlen(path) + strlen(recording[rec]) < RECSIZE)
							strcat(recording[rec], path);
						else
							strncat(recording[rec], path, RECSIZE - strlen(recording[rec]) - 1);     
					}
				}
			} else
				cmpstatus=0;
		}
		if(cmpstatus == 0) {
			if(last) {
				va_end(ap);
				return 0;
			}
		}
		pe = nextpe;
	}
	
	va_end(ap);
	if(_rf_debug && rec_on) fprintf(stderr, "path_match() recording[%d] = \"%s\"\n", rec, recording[rec]);
	return 1;
}

/*
 * Generic regexp
 * Matching groups are store din regex_group[]
 */
int regex(const char *buffer, const char *expr)
{
	pcre *patt;
	int errcode;
	int rc, i;
	int ovector[30];
	
	if(_rf_debug) fprintf(stderr, "regex() compile(\"%s\")\n", expr);
	patt = pcre_compile2(expr,
			     0, /* options: PCRE_ANCHORED PCRE_CASELESS  */
			     &errcode,
			     NULL, NULL,
			     NULL);
	if(!patt) {
		if(_rf_debug) fprintf(stderr, "regex() compile failed: %d\n", errcode);
		return 0;
	}

	rc = pcre_exec(
		patt,             /* result of pcre_compile() */
		NULL,           /* we didn't study the pattern */
		buffer,  /* the subject string */
		strlen(buffer),             /* the length of the subject string */
		0,              /* start at offset 0 in the subject */
		0,              /* default options */
		ovector,        /* vector of integers for substring information */
		30);            /* number of elements (NOT size in bytes) */
	if(_rf_debug) fprintf(stderr, "regex() pcre_exec() == %d\n", rc);	

	if(rc < 0) return 0;
	
	for(i=0;i<rc;i++) {
		int len;
		len = ovector[ (i << 1) + 1 ] - ovector[ (i << 1) ];
		if(len >= RECSIZE) len = RECSIZE-1;
		strncpy(regex_group[i], buffer + ovector[ (i << 1) ], len);
		regex_group[i][len] = 0;
		if(_rf_debug) fprintf(stderr, "regex() regex_group[%d] = \"%s\"\n", i, regex_group[i]);	
	}
	return rc+1;
}

/*
 * Regexp match of path component of the URI.
 */
int path_regex(const char *expr)
{
	char *u = getenv("DOCUMENT_URI");
	if(!u) return 0;
	return regex(u, expr);
}

/*
 * The hostname to send for a proxy-request.
 */
int proxy_host(const char *hostname)
{
	printf("Proxy-host=%s\n", hostname);
	return 0;
}

/*
 * Reverse proxy translation
 */
int proxy_reverse(const char *real, const char *fake)
{
	printf("Proxy-reverse-alias=%s,%s\n", real, fake);
	return 0;
}

/*
 * Proxy request
 */
int _proxy_to(const char *URI, ...)
{
	const char *p;
	va_list ap;

	va_start(ap, URI);
	printf("DOCUMENT_URI=%s", URI);
	
	while( (p=va_arg(ap, char *)) ) {
		printf("%s", p);
	}
	printf("\n");
	va_end(ap);
	return 0;
}

/*
 * We are done processing and return to the request handling.
 */
void done()
{
	_exit(0);
}

void debug()
{
	_rf_debug = 1;
}
