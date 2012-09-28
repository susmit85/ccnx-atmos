#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/time.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/charbuf.h>
#include <ccn/reg_mgmt.h>
#include <ccn/ccn_private.h>
#include <ccn/ccnd.h>
#include <ccn/face_mgmt.h>

#include <ccn/face_mgmt.h>
#include <ccn/hashtb.h>
#include <ccn/indexbuf.h>
#include <ccn/schedule.h>

int f_tmp = INT_MIN;

//ncdump -v time pr_tmp1.nc|tr '\n;}' ' '|awk -F 'data:' '{print $2}'|awk -F 'time = ' '{print $2}'|awk -F ',' '{print $NF}' |sed 's/ //g'

//intermediate node
int local_start = 0;
int local_end = 0;

int flag = 0;
char *filename= NULL;

//data packet format
struct data {
    int num1;
    int num2;
    char *message;
    const unsigned char *next_ccnb;
};

int construct_trace_response(struct ccn *h, struct ccn_charbuf *data,
                             const unsigned char *interest_msg, const struct ccn_parsed_interest *pi, char *mymsg, size_t size, int is_final) {

    //**this function takes the interest, signs the content and returns to
    //upcall for further handling

    //copy the incoming interest name in ccn charbuf
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;

    int res;
#ifdef DEBUG
    printf("Received interest, name length: %Zu\n", size);
#endif

    //get interest name
    res = ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
                             pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    struct ccn_charbuf *uri = ccn_charbuf_create();
    ccn_uri_append(uri, name->buf, name->length, 1);
    printf("Returning data for uri = %s\n", ccn_charbuf_as_string(uri));
    if(res == -1) {
        fprintf(stderr, "Can not copy interest name to buffer\n");
        exit(1);
    }

    //check if this is final reply chunk, set final block flag
    if (is_final)
        sp.sp_flags |= CCN_SP_FINAL_BLOCK;

    //sign the content
    res = ccn_sign_content(h, data, name, &sp,  mymsg, size);
    if(res == -1) {
        fprintf(stderr, "Can not sign content\n");
        exit(1);
    }

    //free memory and return
    ccn_charbuf_destroy(&sp.template_ccnb);
    ccn_charbuf_destroy(&name);
    return res;
}

int get_interest_name(const unsigned char *interest_msg,
                      struct ccn_parsed_interest *pi, char **interest_name,  char **trunk_interest_name) {
    // arguments are interest message and parsed interest. Sets interest name
    // and the random component for further processing
    //number of components and their offset boundaries
    int res;
    struct ccn_charbuf *name = ccn_charbuf_create();

    //copy the name portion from interest
    res = ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
                             pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);

    //calculate timestamp
    char timestamp[200];
    time_t ts = time(NULL);

    //format and print timestamp and interest name
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&ts)) != 0) {
        struct ccn_charbuf *uri = ccn_charbuf_create();
        ccn_uri_append(uri, name->buf, name->length, 1);
        printf("timestamp %s uri = %s\n", timestamp, ccn_charbuf_as_string(uri));
    } else {
        printf("Can not format time\n");
        exit(1);
    }

    //convert the name to string, store in interest_name
    int index = 0;
    char *slash = "/";
    size_t component_size = 0;
    const unsigned char *component = NULL;
    struct ccn_indexbuf *components= ccn_indexbuf_create();

    //get number of components and tmp name
    int num_comps = ccn_name_split(name, components);
    char *tmp_name = malloc(sizeof(char) * pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    char *trunk_tmp_name = malloc(sizeof(char) * pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    if( tmp_name == NULL) {
        fprintf(stderr, "Can not allocate memory for temporary name\n");
        exit(1);
    }
    memset(tmp_name, 0,  pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
    memset(trunk_tmp_name, 0,  pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);

    int new_length = 0;
    int trunk_new_length = 0;

    //append each name component to string
    for(index=0; index<num_comps; index++) {
        res = ccn_name_comp_get(name->buf, components, index, &component, &component_size);
        if (res == -1) {
            fprintf(stderr, "Can not get components from interest name\n");
            exit(1);
        }

#ifdef DEBUG
        printf("Component %d %s\n", index, component);
#endif
        if(index != num_comps) {
            strcat((char *)tmp_name, slash);
            strcat((char *)tmp_name, (char*)component);
            new_length += strlen((const char *)component);
        }

        if(index != num_comps -1) {
            strcat((char *)trunk_tmp_name, slash);
            strcat((char *)trunk_tmp_name, (char*)component);
            trunk_new_length += strlen((const char *)component);
        }
    }

    //we don't need the last component and the trailing slash
    new_length = new_length + num_comps;
    trunk_new_length = trunk_new_length + num_comps -1;
#ifdef DEBUG
    printf("interest name%s %s\n", tmp_name, trunk_tmp_name);
    printf("new_length %d\n", new_length);
#endif

    *interest_name = malloc(sizeof(char) * new_length + 1);
    if( interest_name == NULL) {
        fprintf(stderr, "Can not allocate memory for interest_name\n");
        exit(1);
    }
    strcpy((char *)*interest_name, tmp_name);
    //get the number of components without /trace and random number

    *trunk_interest_name = malloc(sizeof(char) * trunk_new_length + 1);
    if( interest_name == NULL) {
        fprintf(stderr, "Can not allocate memory for interest_name\n");
        exit(1);
    }
    strcpy((char *)*trunk_interest_name, trunk_tmp_name);
    return(0);
}

enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {
    //this is the callback function, all interest matching ccnx:/trace
    //will come here, handle them as appropriate

    int res = 0;

    //buffer where the outgoing object will be stored
    struct ccn_charbuf *data = ccn_charbuf_create();
    char readbuf[80] = {0};
    char filebuf[8193] = {0};
    FILE *f;
    char command[1024];
    memset(command, 0, 1024);
    char *interest_name = NULL;
    char *trunk_interest_name = NULL;


    struct timeval start, end;
    long mtime2, start_time, end_time;

    //switch on type of event
    switch (kind) {
    case CCN_UPCALL_FINAL:
        return CCN_UPCALL_RESULT_OK;
        break;

    case CCN_UPCALL_CONTENT:
        printf("received content\n");
        break;

    case CCN_UPCALL_INTEREST: {
        //received matching interest
        //get the interest name from incoming packet
        res = get_interest_name(info->interest_ccnb, info->pi, &interest_name, &trunk_interest_name);

        //    python script.py 370,380 pr_19020101_060000.nc /pr/365/395/ /pr/365/395/tmp
        if (f_tmp  == INT_MIN) {
            printf("Generating the file\n");

            //invoke data extraction script
            gettimeofday(&start, NULL);
            sprintf(command, "%s %s %s", "python script.py", filename, trunk_interest_name);
            f = popen(command, "r");
            while (fgets(readbuf, 80, f) != NULL) {
                readbuf[strlen(readbuf)-1] = '\0';
            }
            gettimeofday(&end, NULL);
            start_time = ((start.tv_sec) * 1000 + start.tv_usec/1000.0) + 0.5;
            end_time = ((end.tv_sec) * 1000 + end.tv_usec/1000.0) + 0.5;
            mtime2 = end_time - start_time;
            printf("Generation time%ld\n", mtime2);
            f_tmp = open(readbuf,  O_RDONLY);
            if (f_tmp  == -1)
                printf("Can not open file %s\n", readbuf);
        }

        //get data, send response
        int rlen = 0;
        if ((rlen = read(f_tmp, filebuf, 8192)) > 0) {
            //printf("strlen filebuf%d\n", rlen);
            if (rlen < 8192)
                construct_trace_response(info->h, data, info->interest_ccnb, info->pi, filebuf, rlen, 1);
            else
                construct_trace_response(info->h, data, info->interest_ccnb, info->pi, filebuf, rlen, 0);
            res = ccn_put(info->h, data->buf, data->length);
            if (res == -1) {
                printf("can not send response with res = %d\n", res);
                exit(1);
            }
        } else {
            printf("Sent response\n");
            close(f_tmp);
            f_tmp = INT_MIN;
        }
    }
    break;
    default:
        break;
    }
    return(0);
}


int main(int argc, char **argv) {
    //no argument necessary
    if(argc != 2) {
        printf("Usage: ./server filename\n");
        exit(1);
    }

    int res;
    filename = malloc(strlen(argv[1]) + 1);
    strcpy(filename, argv[1]);
    //create ccn handle
    struct ccn *ccn = NULL;

    //connect to CCN
    ccn = ccn_create();
    //NOTE:check for null

    if (ccn_connect(ccn, NULL) == -1) {
        fprintf(stderr, "Could not connect to ccnd");
        exit(1);
    }

    //create prefix we are interested in, register in FIB
    struct ccn_charbuf *prefix = ccn_charbuf_create();

    //We are interested in anythin starting with ccnx:/
    res = ccn_name_from_uri(prefix, "/");
    if (res < 0) {
        fprintf(stderr, "Can not convert name to URI\n");
        exit(1);
    }

    //handle for upcalls, receive notifications of incoming interests and content.
    //specify where the reply will go
    struct ccn_closure in_interest = {.p = &incoming_interest};
    in_interest.data = &prefix;

    //set the interest filter for prefix we created
    res = ccn_set_interest_filter(ccn, prefix, &in_interest);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }

    //listen infinitely
    res = ccn_run(ccn, -1);

    //cleanup
    ccn_destroy(&ccn);
    ccn_charbuf_destroy(&prefix);
    exit(0);
}
