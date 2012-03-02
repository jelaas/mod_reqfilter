diff --git a/modules/proxy/mod_proxy_http.c b/modules/proxy/mod_proxy_http.c
index 19c82f2..131c6b2 100644
--- a/modules/proxy/mod_proxy_http.c
+++ b/modules/proxy/mod_proxy_http.c
@@ -738,7 +738,12 @@ int ap_proxy_http_request(apr_pool_t *p, request_rec *r,
     ap_xlate_proto_to_ascii(buf, strlen(buf));
     e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
     APR_BRIGADE_INSERT_TAIL(header_brigade, e);
-    if (conf->preserve_host == 0) {
+    
+    if((buf = apr_table_get(r->notes, "proxy-host"))) {
+		    if(strncmp(buf, "Host:", 5))
+			    buf = apr_pstrcat(p, "Host: ", buf, CRLF, NULL);
+	    } else {
+    if (conf->preserve_host == 0 ) {
         if (ap_strchr_c(uri->hostname, ':')) { /* if literal IPv6 address */
             if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                 buf = apr_pstrcat(p, "Host: [", uri->hostname, "]:", 
@@ -771,6 +776,7 @@ int ap_proxy_http_request(apr_pool_t *p, request_rec *r,
         }
         buf = apr_pstrcat(p, "Host: ", hostname, CRLF, NULL);
     }
+	    }
     ap_xlate_proto_to_ascii(buf, strlen(buf));
     e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
     APR_BRIGADE_INSERT_TAIL(header_brigade, e);
diff --git a/modules/proxy/proxy_util.c b/modules/proxy/proxy_util.c
index 95f4a78..30a7ef0 100644
--- a/modules/proxy/proxy_util.c
+++ b/modules/proxy/proxy_util.c
@@ -346,6 +346,18 @@ PROXY_DECLARE(request_rec *)ap_proxy_make_fake_req(conn_rec *c, request_rec *r)
 {
     request_rec *rp = apr_pcalloc(r->pool, sizeof(*r));
 
+    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "LISTING R NOTES\n");
+
+    {
+	    const apr_array_header_t *tarr = apr_table_elts(r->notes);
+	    const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
+	    int i;
+	    
+	    for (i = 0; i < tarr->nelts; i++) {
+		    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "key = %s, val = %s\n", telts[i].key, telts[i].val);
+	    }
+    }
+
     rp->pool            = r->pool;
     rp->status          = HTTP_OK;
 
@@ -353,7 +365,7 @@ PROXY_DECLARE(request_rec *)ap_proxy_make_fake_req(conn_rec *c, request_rec *r)
     rp->subprocess_env  = apr_table_make(r->pool, 50);
     rp->headers_out     = apr_table_make(r->pool, 12);
     rp->err_headers_out = apr_table_make(r->pool, 5);
-    rp->notes           = apr_table_make(r->pool, 5);
+    rp->notes           = apr_table_copy(r->pool, r->notes);
 
     rp->server = r->server;
     rp->proxyreq = r->proxyreq;
@@ -1075,6 +1087,30 @@ PROXY_DECLARE(const char *) ap_proxy_location_reverse_map(request_rec *r,
     else {
         ent = (struct proxy_alias *)conf->raliases->elts;
     }
+
+    // JEL
+    if(apr_table_get(r->notes, "proxy-ralias")) {
+	    const apr_array_header_t *tarr = apr_table_elts(r->notes);
+	    const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
+	    int i;
+	    const char *real, *fake;
+	    
+	    for (i = 0; i < tarr->nelts; i++) {
+		    if(strcmp(telts[i].key, "proxy-ralias")==0) {
+			    real = telts[i].val;
+			    fake = strchr(real, ',');
+			    if(!fake) continue;
+			    l2 = fake-real;
+			    fake++;
+			    while(isspace(*fake)) fake++;
+			    if (l1 >= l2 && strncasecmp(real, url, l2) == 0) {
+				    u = apr_pstrcat(r->pool, ent[i].fake, &url[l2], NULL);
+				    return ap_construct_url(r->pool, u, r);
+			    }
+		    }
+	    }
+    }
+
     for (i = 0; i < conf->raliases->nelts; i++) {
         proxy_server_conf *sconf = (proxy_server_conf *)
             ap_get_module_config(r->server->module_config, &proxy_module);
