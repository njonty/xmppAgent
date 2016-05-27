#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
	X_CRID
}X_OPTION_TYPE;

typedef struct _x_msg_option
{
	char type;
	char len;
	char value[0];
}x_msg_option;

void send_xmsg(char *xbuf, int bufLen )
{
    int sockfd, portno, serverlen,n, i;
    struct sockaddr_in serveraddr;

	printf("pkt size : %d", bufLen);
for(i=0; i < bufLen; i++)
{
	printf(" %02x",*( xbuf+i));
}
fflush(0);
//return;
    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
printf("test1");
fflush(0);   
 
    serveraddr.sin_family = AF_INET;
printf(" test2");
fflush(0);   
 
     inet_aton("127.0.0.1", &serveraddr.sin_addr.s_addr);

printf(" test3");
fflush(0);   
 
    serveraddr.sin_port = htons(reversePort);
   /* send the message to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, xbuf, bufLen, 0, &serveraddr, serverlen);
    if (n < 0) 
      error("ERROR in sendto");
printf("bytes sent : %d", n);
fflush(0);    
    /* print the server's reply */
    n = recvfrom(sockfd, xbuf, 1024, 0, &serveraddr, &serverlen);
    if (n < 0) 
      error("ERROR in recvfrom");

    	
    return;
}

void x_add_option(X_OPTION_TYPE opType , char *xMsg, char* value )
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


void x_build_CR_header(char* xMsg )
{
	x_msg_hdr *hdr= ( x_msg_hdr * ) xMsg;

	hdr->type = CR_REQ;
	hdr->len=0;
	return;
}



int create_cr_req_msg(char *xMsg ,char *username, char *password, char *id)
{
	x_msg_option *opt;
	int len;

	x_build_CR_header(xMsg );
	x_add_option(X_USERNAME, xMsg, username );
	x_add_option(X_PASSWORD, xMsg, password );
	x_add_option(X_CRID, xMsg,id );

	return ((x_msg_hdr *) xMsg)->len + X_MSG_HDR_SZ ;
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
	xmpp_stanza_t *reply, *cr, *username, *pwd,  *text, *body;
	char *unameStr,*pwdStr , *replytext,*buf, xMsg[1024];
        size_t len;
	int xbufLen;

	xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;

	cr = xmpp_stanza_get_child_by_name(stanza, "connectionRequest")	;
	if(!cr) return 1;

	username = xmpp_stanza_get_child_by_name(cr, "username")	;
	if(!cr) return 1;

	pwd = xmpp_stanza_get_child_by_name(cr, "password")	;
	if(!pwd) return 1;

	unameStr = xmpp_stanza_get_text(username);
	pwdStr = xmpp_stanza_get_text(pwd);

	printf("\n calling create_cr");
	fflush(0);

	xbufLen = create_cr_req_msg(xMsg, "iotina" /*unameStr*/,"hello123"/* pwdStr*/, "id");
	printf("\n calling sendMsg");
	fflush(0);
	send_xmsg(xMsg, xbufLen );
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

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid, *pass;
    /* take a jid and password on the command line */
    if (argc != 4) {
	fprintf(stderr, "Usage: xmppAgent <jid> <pass> <reverse port>\n\n");
	return 1;
    }
    
    jid = argv[1];
    pass = argv[2];
    reversePort = atoi(argv[3] );

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
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

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
