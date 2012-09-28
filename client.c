#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

int f_tmp = INT_MIN;
FILE *p = NULL;
int retry_count = 0;
int flag = 0;
char *out_file = NULL;

int get_content_name(const unsigned char *interest_msg,  
struct ccn_parsed_interest *pi, char **interest_name,  char **new_interest_name) {
    // argumennts are interest message and parsed interest. Sets interest name
    // and the random component for further processing
    //-----------------------------------------------------------------------//

    //number of components and their offset boundaries
    int res;
    struct ccn_charbuf *name = ccn_charbuf_create();

    //copy the name portion from interest
    res = ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
                             pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    //convert the name to string, store in interest_name
    int index = 0;
    char *slash = "/";
    size_t component_size = 0;
    const unsigned char *component = NULL;
    struct ccn_indexbuf *components= ccn_indexbuf_create();

    //get number of components
    int num_comps = ccn_name_split(name, components);
    char *tmp_name = malloc(sizeof(char) * pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    int new_comp = 0;
    char new_component[80] = {0};
    if( tmp_name == NULL) {
        fprintf(stderr, "Can not allocate memory for temporary name\n");
        exit(1);
    }
    memset(tmp_name, 0,  pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    int new_length = 0;

    //append each name component to string, remove first component, "/trace"
    for(index=0; index<num_comps; index++) {
        res = ccn_name_comp_get(name->buf, components, index, &component, &component_size);
        if (res == -1) {
            fprintf(stderr, "Can not get components from interest name\n");
            exit(1);
        }
        //insert slash between components, except for the last one
        if(index != num_comps - 1) {
            strcat((char *)tmp_name, slash);
            strcat((char *)tmp_name, (char*)component);
            new_length += strlen((const char *)component);
        }

        if(index == num_comps - 1) {
            sscanf((const char *)component, "%d", &new_comp);
            new_comp += 1;
            sprintf(new_component, "%d", new_comp);
            // printf("new_component %d %s \n", new_comp, new_component);
            strcat((char *)tmp_name, slash);
            strcat((char *)tmp_name, (char*)new_component);
            new_length += strlen((const char *)new_component);
        }
    }

    //set the interest name
    //we don't need the last component and the trailing slash
    new_length = new_length + num_comps;
#ifdef DEBUG
    printf("interest name%s \n", tmp_name);
    printf("new_length %d\n", new_length);
#endif

    *new_interest_name = malloc(sizeof(char) * new_length + 1);
    if(*new_interest_name == NULL) {
        fprintf(stderr, "Can not allocate memory for interest_name\n");
        exit(1);
    }
    strcpy((char *)*new_interest_name, tmp_name);
    return(0);
}

enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {

    //this is the callback function, all interest matching ccnx:/trace
    //will come here, handle them as appropriate
    int res = 0;
    const unsigned char *ptr;
    size_t length;

    char *interest_name = NULL;
    char *new_interest_name = NULL;

    //switch on type of event
    switch (kind) {
    case CCN_UPCALL_FINAL:
        return CCN_UPCALL_RESULT_OK;
        break;

    case CCN_UPCALL_CONTENT:
        printf("received content\n");
        printf("\n****************************\n");
        res = ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &ptr, &length);
        res = get_content_name(info->interest_ccnb, info->pi, &interest_name, &new_interest_name);
        if(res < 0) {
            printf("Bad content\n");
            exit(1);
        }
        printf("Next interest name%s\n", new_interest_name);

        //check the permission
        //if (f_tmp == INT_MIN)
        if( p == NULL) {
            //f_tmp = open("pr_test.nc",  O_WRONLY);
            p = fopen(out_file, "w");
            if (p == NULL) {
                perror("open");
                exit(1);
            }
        }
        //write(f_tmp, ptr, length);
        fwrite(ptr, length, 1, p);

        //**size**//
        printf("size =%zu\n", length);

        //allocate memory for interest
        struct ccn_charbuf *ccnb = ccn_charbuf_create();

        //adding name to interest
        res = ccn_name_from_uri(ccnb, new_interest_name);

        if (!ccn_is_final_block(info)) {
            ccn_express_interest(info->h, ccnb, selfp, NULL);
        } else {
            //send the last interest to close this
            fclose(p);
            exit(0);
        }
        break;

    case CCN_UPCALL_INTEREST_TIMED_OUT:
        printf("request timed out - retrying\n");
        retry_count ++;
        if (retry_count == 3)
            exit(1);
        return CCN_UPCALL_RESULT_REEXPRESS;

    case CCN_UPCALL_CONTENT_UNVERIFIED:
        printf("Could not verify content");
        return CCN_UPCALL_RESULT_ERR;

    case CCN_UPCALL_CONTENT_BAD:
        printf("Bad content, verification failed\n");
        return CCN_UPCALL_RESULT_ERR;

    case CCN_UPCALL_INTEREST:
        //don't care about interests
        break;

    default:
        printf("Unexpected response\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    return(0);
}

int main (int argc, char **argv) {
    int res;

    //check if user supplied uri to trace
    if(argv[1] == NULL || argv[2] == NULL) {
        printf("Usage: client URI out_file(URI format is /name/arg/365,390\n");
        exit(1);
    }

    out_file = malloc(strlen(argv[2])+1);
    strcpy(out_file, argv[2]);

    //get the length of user provided URI
    int argv_length = strlen(argv[1]);

    //check first six chars for ccnx:/, if present, skip them
    int skip = 0;
    res = strncmp("ccnx:/", argv[1], 6);
    if(res == 0) {
        skip = 5;
    }

    //if URI does not begins with /, exit
    if (argv[1][skip] != '/') {
        printf("URI must begin with /\n");
        exit(1);
    }

    //check if uri ends with slash, append if missing
    char *slash = "";
    if (argv[1][argv_length-1] != '/') {
        slash = "/";
    }

    //allocate memory for trace URI = /trace/user_input/random_number
    char *URI = (char *) malloc(sizeof(char)*+argv_length+1); //find size of rand
    if(URI == NULL) {
        fprintf(stderr, "Can not allocate memory for URI\n");
        exit(1);
    }

    //put together the trace URI, add a random number to end of URI
    sprintf(URI, "%s%s", argv[1]+skip, slash);

#ifdef DEBUG
    printf("URI %s\n", URI);
#endif

    //allocate memory for interest
    struct ccn_charbuf *ccnb = ccn_charbuf_create();

    //adding name to interest
    res = ccn_name_from_uri(ccnb, URI);

    //create the ccn handle
    struct ccn *ccn = ccn_create();

    //connect to ccnd
    res = ccn_connect(ccn, NULL);
#ifdef DEBUG
    printf("Connected to CCND, return code: %d\n", res);
#endif

    printf("expressing interest\n");
    struct ccn_closure *incoming;
    incoming = calloc(1, sizeof(*incoming));
    incoming->p = incoming_interest;
    res = ccn_express_interest(ccn, ccnb, incoming, NULL);
    if (res == -1) {
        fprintf(stderr, "Could not express interest for %s\n", argv[1]);
        exit(1);
    }

    //run for timeout miliseconds
    res = ccn_run(ccn, -1);
    if (res < 0) {
        fprintf(stderr, "ccn_run error\n");
        exit(1);
    }
    exit(0);
}
