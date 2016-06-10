#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef OPENWRT
#include <uci.h>
#include "suci.h"
#endif

xmpp_conn_t *conn;
xmpp_ctx_t *ctx;
#define XMPP_NS_CR "urn:broadband-forum-org:cwmp:xmppConnReq-1-0"
#define XMPP_NS_CR_STZ "urn:ietf:params:xml:ns:xmpp-stanzas"

int reversePort=0;
#define X_OPTION_HDR_SZ 2 //8 bytes
#define X_MSG_HDR_SZ 2 //8 bytes

/* reverse msg format 
type : 1 byte :CR Req=0,CR Res=1
len : 1 byte
value : variable option

TLV option list

Valid options

username : type 1
password : type 2
crid : type 3

*/

typedef enum _REQ_TYPE
{
	CR_REQ = 0,
	CR_RESP
}REQ_TYPE;

typedef struct _x_msg_hdr
{
	char type;
	char len;
	char value[0];
}x_msg_hdr;

typedef enum _X_OPTION_TYPE
{
	X_USERNAME = 0,
	X_PASSWORD,
	X_CRID,
	X_FROM,
	X_STATUS
}X_OPTION_TYPE;

typedef struct _x_msg_option
{
	char type;
	char len;
	char value[0];
}x_msg_option;

typedef struct _cr_info {
	xmpp_conn_t * conn;
	xmpp_stanza_t * stanza;
	void * userdata;
}cr_info;

typedef struct _send_info {
	char* xMsg;
	int xbufLen;
}send_info;

void x_get_CR_header(char* xMsg,x_msg_hdr **hdr  );
char* x_get_option(X_OPTION_TYPE opType , char *xMsg );


void stanza_reply(char *errstr, char* to, char *id, char *username, char*password )
{
	xmpp_stanza_t *iq;

	iq = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(iq, "iq");
        xmpp_stanza_set_id(iq, id);
        xmpp_stanza_set_to(iq, to);

printf("\ntest1");
fflush(0);   
 


	if(strcmp(errstr,"success" )== 0 )
	{
	        xmpp_stanza_set_type(iq, "result");
	}
	else
	{
		xmpp_stanza_t *err, *n_auth , *cr_resp, *uname, *text_stanza, *pwd;
	        xmpp_stanza_set_type(iq, "error");

	        cr_resp = xmpp_stanza_new(ctx);
       		xmpp_stanza_set_name(cr_resp, "connectionRequest");
        	xmpp_stanza_set_ns(cr_resp, XMPP_NS_CR);
        	xmpp_stanza_add_child(iq, cr_resp);

        	uname = xmpp_stanza_new(ctx);
        	xmpp_stanza_set_name(uname, "username");

        	text_stanza = xmpp_stanza_new(ctx);
        	xmpp_stanza_set_text(text_stanza,username);

        	xmpp_stanza_add_child( uname,text_stanza );
        	xmpp_stanza_release(text_stanza);


        	text_stanza = xmpp_stanza_new(ctx);
        	pwd = xmpp_stanza_new(ctx);
        	xmpp_stanza_set_name(pwd, "password");

        	text_stanza = xmpp_stanza_new(ctx);
        	xmpp_stanza_set_text(text_stanza, password);

        	xmpp_stanza_add_child(pwd,text_stanza);

        	xmpp_stanza_add_child(cr_resp,uname);
        	xmpp_stanza_add_child(cr_resp,pwd);

		if( strcmp(errstr,"not-authorized" )== 0)
		{
			xmpp_stanza_t *n_auth;

		//not authorized
		        err = xmpp_stanza_new(ctx);

	       		xmpp_stanza_set_name(err, "error");
	        	xmpp_stanza_add_child(iq, err);
		        xmpp_stanza_set_type(err, "cancel");

		        n_auth = xmpp_stanza_new(ctx);

	       		xmpp_stanza_set_name(n_auth, "not-authorized");
	        	xmpp_stanza_add_child( err, n_auth);
	        	xmpp_stanza_set_ns( n_auth, XMPP_NS_CR_STZ);
			
			/* we can release the stanza since it belongs to cr_resp now now */
		        xmpp_stanza_release(err);
        		xmpp_stanza_release(n_auth);
		}
		else
		{
			xmpp_stanza_t *s_unavail;

		//service not available
		        err = xmpp_stanza_new(ctx);

	       		xmpp_stanza_set_name(err, "error");
	        	xmpp_stanza_add_child(iq, err);
		        xmpp_stanza_set_type(err, "cancel");
			xmpp_stanza_set_attribute(err, "code", "503");

		        s_unavail = xmpp_stanza_new(ctx);

	       		xmpp_stanza_set_name(s_unavail, "service-unavailable");
	        	xmpp_stanza_add_child( err, s_unavail);
	        	xmpp_stanza_set_ns( s_unavail, XMPP_NS_CR_STZ);
			
			/* we can release the stanza since it belongs to cr_resp now now */
		        xmpp_stanza_release(err);
        		xmpp_stanza_release(s_unavail);

		}
	       /* we can release the stanza since it belongs to iq now */
        	xmpp_stanza_release(text_stanza);
        	xmpp_stanza_release(cr_resp);
        	xmpp_stanza_release(uname);
        	xmpp_stanza_release(pwd);

	}
printf("\ntest2");
fflush(0);   
 
        /* set up reply handler */
//        xmpp_id_handler_add(conn, handle_reply, "active1", ctx);

        /* send out the stanza */
        xmpp_send(conn, iq);

        /* release the stanza */
        xmpp_stanza_release(iq);

}


void send_xmsg(char *xbuf, int bufLen )
{
    int sockfd, portno, serverlen,n, i;
    struct sockaddr_in serveraddr;
    x_msg_hdr *hdr;

	printf("\npkt size : %d ", bufLen);
for(i=0; i < bufLen; i++)
{
	printf(" %02x",*( xbuf+i));
}
fflush(0);
//return;
    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        error("ERROR opening socket");
	return;
    }
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
//printf("test1");
//fflush(0);   
 
    serveraddr.sin_family = AF_INET;
//printf(" test2");
//fflush(0);   
 
     inet_aton("127.0.0.1", &serveraddr.sin_addr.s_addr);

//printf(" test3");
//fflush(0);   
 
    serveraddr.sin_port = htons(reversePort);
   /* send the message to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, xbuf, bufLen, 0, &serveraddr, serverlen);
    if (n < 0) 
      error("ERROR in sendto");

printf("\nbytes sent : %d", n);
fflush(0);    


    /* print the server's reply */

    n = recvfrom(sockfd, xbuf, 1024, 0, &serveraddr, &serverlen);
    if (n < 0) 
      error("ERROR in recvfrom");

printf("\nbytes sent : %d", n);
fflush(0);    

    x_get_CR_header(xbuf, &hdr);

	//only handle CR response
    if(hdr->type ==CR_RESP )
    {
	int i;
	char *status,*uname,*pwd,*id,*to;

	id= x_get_option(X_CRID , xbuf );
	to= x_get_option(X_FROM , xbuf );

	uname= x_get_option(X_USERNAME , xbuf );
	pwd= x_get_option(X_PASSWORD , xbuf );

	status = x_get_option(X_STATUS , xbuf );

	if(status )
	{
	     	stanza_reply(status,to ,id ,uname,pwd);
	}
    }


   	
    return;
}

void send_xmsg_thread( void *info)
{
	send_xmsg(((send_info*)info)->xMsg, ((send_info*)info)->xbufLen );	
}




void x_add_option(X_OPTION_TYPE opType , char *xMsg, const char* value )
{
	x_msg_hdr *hdr= (x_msg_hdr *) xMsg;
	x_msg_option *optPtr;
	optPtr =( x_msg_option *) ( xMsg + hdr->len + X_MSG_HDR_SZ);

	//set the hdr len taking the new option into account
	hdr->len += strlen(value) + 1 + X_OPTION_HDR_SZ;

	//populate the new option
	optPtr->type = opType;
	optPtr->len = strlen(value)+1;
	strcpy(optPtr->value, value );
	optPtr->value[optPtr->len]='\0';
	return ;
}



char * x_get_option(X_OPTION_TYPE opType , char *xMsg )
{
	x_msg_hdr *hdr= (x_msg_hdr *) xMsg;
	x_msg_option *optPtr;
	int i=0;

	optPtr =( x_msg_option *) hdr->value;

printf("\nmsg len : %d", hdr->len);
fflush(0);    


	for(i=hdr->len; i>0 ;optPtr=( x_msg_option *)(((char*)optPtr)+optPtr->len + X_OPTION_HDR_SZ) )
	{
		if(optPtr->type == opType )
		{
			printf("\n match : %s",  (char*)optPtr->value);
			return (char*)optPtr->value;
		}

		i -= optPtr->len + X_OPTION_HDR_SZ;
printf("\noption len : %d remaining len : %d", optPtr->len, i);
fflush(0);    


	}
	return NULL;
}




void x_build_CR_header(char* xMsg )
{
 	x_msg_hdr *hdr= ( x_msg_hdr * ) xMsg;

	hdr->type = CR_REQ;
	hdr->len=0;
	return;
}

void x_get_CR_header(char* xMsg,x_msg_hdr **hdr  )
{
	*hdr= ( x_msg_hdr * ) xMsg;

	return;
}



int create_cr_req_msg(char *xMsg ,char *username, char *password, char *id, const char* from)
{
	x_msg_option *opt;
	int len;

	x_build_CR_header(xMsg );
	x_add_option(X_USERNAME, xMsg, username );
	x_add_option(X_PASSWORD, xMsg, password );
	x_add_option(X_CRID, xMsg,id );
	x_add_option(X_FROM, xMsg,from );

	return ((x_msg_hdr *) xMsg)->len + X_MSG_HDR_SZ ;
}


int process_cr(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
	xmpp_stanza_t *reply, *cr, *username, *pwd,  *text, *body;
	char *unameStr,*pwdStr , *replytext,*buf, *xMsg=malloc(1024);
	const char * from, *id;
        size_t len;
	int xbufLen, iret1;
	pthread_t thread1;
	int iret;
	send_info *info=malloc(sizeof(send_info ));

	xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;

	printf("\n inside process_cr");
	fflush(0);

	from = xmpp_stanza_get_from(stanza);
	id =  xmpp_stanza_get_id(stanza);

	cr = xmpp_stanza_get_child_by_name(stanza, "connectionRequest")	;
	if(!cr) return 1;
	printf("\n inside process_cr 1");
	fflush(0);


	username = xmpp_stanza_get_child_by_name(cr, "username")	;
	if(!cr) return 1;

	pwd = xmpp_stanza_get_child_by_name(cr, "password")	;
	if(!pwd) return 1;

	unameStr = xmpp_stanza_get_text(username);
	pwdStr = xmpp_stanza_get_text(pwd);

	printf("\n calling create_cr");
	fflush(0);

	xbufLen = create_cr_req_msg(xMsg, unameStr, pwdStr, id, from );
	printf("\n calling sendMsg");
	fflush(0);

	info->xMsg = xMsg;
	info->xbufLen = xbufLen;


	iret = pthread_create( &thread1, NULL, send_xmsg_thread, (void*) info);
     	if(iret)
     	{
        	printf("Error - pthread_create() return code: %d\n",iret);
         	exit(EXIT_FAILURE);
     	}

//	send_xmsg(xMsg, xbufLen );

	return 0;
}



void *cr_handler_thread( void *ptr )
{
	xmpp_conn_t * conn;
	xmpp_stanza_t * stanza;
	void * userdata;
	cr_info *info = ( cr_info *)ptr ;


	printf("\n handler thread called");
	fflush(0);
	conn = info->conn;
	stanza = info->stanza;
	userdata = info->userdata;

	process_cr(conn, stanza, userdata );

}

/** Create a stanza object in reply to another.
 *  This function makes a copy of a stanza object with the attribute “to” set
 *  its original “from”.
 *  The stanza will have a reference count of one, so the caller does not
 *  need to clone it.
 *
 *  @param stanza a Strophe stanza object
 *
 *  @return a new Strophe stanza object
 *
 *  @ingroup Stanza
 */
int cr_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
	pthread_t thread1;
	int iret;
	cr_info *info = malloc(sizeof( cr_info));
	info->conn = conn;
	info->stanza = stanza;
	info->userdata = userdata;

	cr_handler_thread((void*)info );
/*	
	iret = pthread_create( &thread1, NULL, cr_handler_thread, (void*) info);
     	if(iret)
     	{
        	printf(stderr,"Error - pthread_create() return code: %d\n",iret);
         	exit(EXIT_FAILURE);
     	}
*/
//	printf("Incoming message from %s: %s\n", xmpp_stanza_get_from(stanza), unameStr);

//	xmpp_stanza_release(cr);
//	xmpp_stanza_release(username);
//	xmpp_stanza_release(pwd);
#if 0
	reply = xmpp_stanza_reply(stanza);

	if (xmpp_stanza_get_type(reply) == NULL)
	    xmpp_stanza_set_type(reply, "chat");

	body = xmpp_stanza_new(ctx);
	xmpp_stanza_set_name(body, "body");
	replytext = (char *) malloc(strlen(" to you too!") + 1);

	strcpy(replytext, " to you too!");
	
	text = xmpp_stanza_new(ctx);

	xmpp_stanza_set_name(text, "replytext");

	xmpp_stanza_add_child(body, text);
	xmpp_stanza_add_child(reply, body);
	xmpp_stanza_release(body);
	xmpp_stanza_release(text);

//        xmpp_stanza_to_text(reply,&buf,&len );
//        xmpp_debug(conn->ctx,"xmpp","Outgoing message from %s: %s\n", xmpp_stanza_get_from(stanza), buf);
fflush(0);	

//xmpp_debug(conn->ctx, "xmpp", "proceeding with TLS");

	xmpp_send(conn, reply);
//	xmpp_stanza_release(reply);
//	free(replytext);
#endif
	return 1;
}




/* define a handler for connection events */
void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status, 
		  const int error, xmpp_stream_error_t * const stream_error,
		  void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    if (status == XMPP_CONN_CONNECT) {
	xmpp_stanza_t* pres;
	fprintf(stderr, "DEBUG: connected\n");
	xmpp_handler_add(conn,cr_handler, NULL, "iq", NULL, ctx);
	
	/* Send initial <presence/> so that we appear online to contacts */
	pres = xmpp_stanza_new(ctx);
	xmpp_stanza_set_name(pres, "presence");
	xmpp_send(conn, pres);
	xmpp_stanza_release(pres);
    }
    else {
	fprintf(stderr, "DEBUG: disconnected\n");
	xmpp_stop(ctx);
    }
}


void x_get_uci(char *cmd,char *value,int len )
{
	FILE *fp;
  	char path[1024];

	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}

  	/* Read the output a line at a time - output it. */
  	while (fgets(path, sizeof(path)-1, fp) != NULL) {
    		printf("%s", path);
  	}
	if(strlen(path) < len)
	{
		memcpy(value,path,strlen(path) );
	}
  	/* close */
  	pclose(fp);
}




void 	x_generate_jid(char *local,char *domain,char *resource,char *jid )
{
	if(resource )
		sprintf(jid,"%s@%s/%s",local,domain,resource);
	else
		sprintf(jid,"%s@%s,local,domain");

	return;
}







int main(int argc, char **argv)
{
    xmpp_log_t *log;
    char jid[1024], *pass[128], *alias,*port,cmd[128]={0},local[256]={0},domain[256]={0},resource[256]={0}, port_str[256]={0},pid_str[32];
    int instance,connection=0,ret=0,pid;
    /* take a jid and password on the command line */
    if (argc != 2 && argc != 4) {
	fprintf(stderr, "Usage: xmppAgent <alias>\n\n");
	return 1;
    }
  
    instance = atoi(argv[1]);

//    instance = x_get_instance(alias);
 
    if( argc == 2)
    {
#ifdef OPENWRT

	sprintf(cmd,"foo.%d.Username",instance);
       	ret = do_uci_get( cmd, local);
	if(ret)
	{
		printf("XMPP: No local part");
		exit(1);
	}

	sprintf(cmd,"foo.%d.Resource",instance);
       	ret = do_uci_get( cmd, resource);
	if(ret)
	{
		printf("XMPP: No Resource part");
	}
	sprintf(cmd,"foo.%d.Domain",instance);
       	ret = do_uci_get( cmd, domain);
	if(ret)
	{
		printf("XMPP: No domain part");
		exit(1);
	}

	sprintf(cmd,"foo.%d.Password",instance);
       	ret = do_uci_get( cmd, pass);
	if(ret)
	{
		printf("XMPP: No password");
		exit(1);
	}

	x_generate_jid(local,domain,resource,jid );

       	ret = do_uci_get( "xmpp.1.port", port_str);
	if(ret)
	{
		printf("XMPP: No reverse port");
		exit(1);
	}


    	reversePort = atoi(port_str );


#endif
    }
    else 
    {
    	strcpy(jid, argv[1]);
    	strcpy(pass, argv[2]);
    	reversePort = atoi(argv[3] );
    }

    pid = getpid();
    sprintf(cmd,"foo.%d.clientpid",instance);
    sprintf(pid_str,"%d",pid);

    ret = do_uci_set( cmd, pid_str);
    if(ret)
    {
	printf("XMPP: Instance not found");
	exit(1);
    }

    ret = do_uci_commit("foo");
    if(ret)
    {
   	 exit(1);
    }


    /* init library */
    xmpp_initialize();

    /* create a context */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG); /* pass NULL instead to silence output */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /*
     * also you can disable TLS support or force legacy SSL
     * connection without STARTTLS
     *
     * see xmpp_conn_set_flags() or examples/basic.c
     */

    /* setup authentication information */
printf("\n Setting the JID");
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);
printf("\n Connecting the client");

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, ctx);

    /* enter the event loop - 
       our connect handler will trigger an exit */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}
