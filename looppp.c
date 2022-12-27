#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aktool.h"
#include <libakrypt.h>


#ifdef AK_HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef AK_HAVE_SYSSTAT_H
#include <sys/stat.h>
#endif

int aktool_digsign_help( void ){
    printf(
            _("aktool ds -n [алгоритм электронной подписи] -p [имя куда секретный ключ] -c [имя куда сертификат] "
              "- digital signature for file generation \n\n"));
    printf(
            _("aktool ds -s [filename of secret key] -d [filename of document] - digital signature for file generation \n\n"));
    printf(
            _("aktool ds -s [filename of certificate] -v [filename of document] - verifying digital signature for file\n\n"));
    printf(
            _("options used for customizing a public key's certificate:\n"));
    aktool_print_common_options();

    printf(_("for usage examples try \"man aktool\"\n" ));

    return EXIT_SUCCESS;
}

typedef enum {
    show_all, show_algoid, show_number, show_resource, show_public_key, show_curveoid, show_label
} what_show_t;

int aktool_key_new1( void );
ak_tlv aktool_key_input_name1( void );
int aktool_key_new_blom_pairwise1( void );
int aktool_key_new_keypair1( bool_t );
int aktool_key_show_key1( char *, what_show_t );


#define aktool_magic_number (113)


int digsign(int argc, tchar *argv[]){

    int next_option = 0, exit_status = EXIT_FAILURE;
    //what_show_t what_show = show_all;

    enum { do_nothing, do_new, create_sign, do_ver} work = do_nothing;

    memset( &ki, 0, sizeof( aktool_ki_t ));
    ki.format = asn1_der_format;
    ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );
    ki.no_outpass = ak_false;
    ki.days = 365;
    ak_certificate_opts_create( &ki.cert.opts );




    struct random gen;
    ak_random_create_lcg(&gen);
    ak_uint8 sign[128];
    struct signkey sk;
    char filesig[128];
    char fileout[128];
    char signature[128];
    char filever[128];
    struct file ofp, aaa;
    struct request req;
    ak_asn1 root = NULL;
    int error = ak_error_ok;


    const struct option long_options[] = {
            { "verify_file",                 1, NULL,  'v' },
            { "file",                 1, NULL,  'd' },
            { "signature",                 1, NULL,  's' },
            { "new",                 1, NULL,  'n' },
            { "new_cert",                 1, NULL,  'c' },
            { "verify_key",                 1, NULL,  'p' }

    };
    do {
        next_option = getopt_long(argc, argv, "hs:d:v:p:n:c:", long_options, NULL);

        switch (next_option){

            case 's':
                ak_realpath( optarg , signature, sizeof( signature ) - 1 );
                break;

            case 'd':
                work = create_sign;
                strcpy(fileout, optarg);
                strcat(fileout, "-signf");
                ak_realpath( optarg , filesig, sizeof( filesig ) - 1 );
                break;

            case 'v':
                work = do_ver;
                strcpy(fileout, optarg);
                strcat(fileout, "-signf");
                ak_realpath( optarg , filever, sizeof( filever ) - 1 );
                break;

            case 'p':
                ak_realpath( optarg , ki.os_file, sizeof( ki.os_file ) - 1 );
                break;

            case 'c':
                ak_realpath( optarg , ki.op_file, sizeof( ki.op_file ) - 1 );
                break;

            case 'n' :
                work = do_new;
                if( strncmp( optarg, "undefined", 9 ) == 0 ) {
                    ki.oid_of_target = NULL;
                    ki.target_undefined = ak_true;
                    break;
                }
                ki.target_undefined = ak_false;
                if(( ki.oid_of_target = ak_oid_find_by_ni( optarg )) == NULL ) {
                    aktool_error(_("using unsupported name or identifier (%s) "), optarg );
                    printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                    return EXIT_FAILURE;
                }
                if( ki.oid_of_target->mode != algorithm ) {
                    aktool_error(_("%s (%s) is not valid identifier for algorithm"),
                                 optarg, ak_libakrypt_get_mode_name( ki.oid_of_target->mode ));
                    printf(
                            _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                    return EXIT_FAILURE;
                }
                break;

            default:
                break;
        }
    } while( next_option != -1 );
    if( work == do_nothing ) return aktool_digsign_help();

    if( !aktool_create_libakrypt( )) return EXIT_FAILURE;


    if( work == do_new ) {
        if(( ki.generator = aktool_key_new_generator()) == NULL ) {
            aktool_error(_("incorrect creation of random sequences generator"));
            exit_status = EXIT_FAILURE;
        }
        else {
            ak_random gptr = ki.generator;
            exit_status = aktool_key_new1();
            ak_ptr_wipe( &ki, sizeof( aktool_ki_t ), gptr );
            aktool_key_delete_generator( gptr );
        }
    }


    if( work == create_sign ) {

        if( ak_skey_import_from_file( &sk, sign_function, signature ) != ak_error_ok )
            return EXIT_FAILURE;

        ak_signkey_sign_file( &sk, &gen, filesig, sign, sizeof( sign ));

        ak_random_destroy( &gen );
        printf("Электронная подпись создана: %s...\n", ak_ptr_to_hexstr(sign, 8, ak_false));

        ak_file_create_to_write(&ofp, fileout);
        ak_file_write(&ofp, sign, 128);

        ak_signkey_destroy( &sk );

    }
    if( work == do_ver ) {


        ak_asn1_import_from_file( root = ak_asn1_new(), signature, NULL );
        ak_request_import_from_asn1( &req, root );

        ak_file_open_to_read(&aaa, fileout);
        ak_file_read(&aaa, sign, 128);

        printf("verify: ");
        if( ak_verifykey_verify_file( &req.vkey, filever, sign )) printf("Ok\n\n");
        else { printf("Wrong\n\n"); }
    }


    aktool_destroy_libakrypt();
    return exit_status;
}

int aktool_key_new1( void )
{

    if( ki.method != NULL ) {
        switch( ki.method->engine ) {
            case blom_pairwise: return aktool_key_new_blom_pairwise1();

            default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                    "does not used as key generation algorithm"),
                                  ki.method->name[0], ki.method->id[0], ak_libakrypt_get_engine_name( ki.method->engine ));
        }
        return EXIT_FAILURE;
    }


    if( ki.oid_of_target == NULL ) {
        aktool_error(_("use --target option and set the name or identifier "
                       "of cryptographic algorithm for a new key"));
        return EXIT_FAILURE;
    }


    switch( ki.oid_of_target->engine ) {
        case block_cipher:
        case hmac_function:
            return aktool_key_new_keypair1( ak_false );
        case sign_function:
            return aktool_key_new_keypair1( ak_true );

        default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                "does not use a cryptographic key"),
                              ki.oid_of_target->name[0], ki.oid_of_target->id[0],
                              ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}



static void aktool_key_new_blom_pairwise_keyname( void )
{
    time_t atime = time( NULL );
    struct hash ctx;
    ak_uint8 buffer[64];


    memset( buffer, 0, sizeof( buffer ));
    memcpy( buffer, ki.userid, ak_min( (size_t) ki.lenuser, sizeof( buffer )));
    memcpy( buffer + ( sizeof( buffer ) - sizeof( time_t )), &atime, sizeof( time_t ));

    ak_hash_create_streebog512( &ctx );
    ak_hash_ptr( &ctx, buffer, sizeof( buffer ), buffer, sizeof( buffer ));
    ak_hash_destroy( &ctx );
    ak_snprintf( ki.os_file, sizeof( ki.os_file ),
                 "%s-pairwise.key", ak_ptr_to_hexstr( buffer, 8, ak_false ));

    if( ki.verbose ) printf(_("generated a new filename: %s\n"), ki.os_file );
}



int aktool_key_new_blom_pairwise1( void )
{
    struct blomkey abonent;
    int exitcode = EXIT_FAILURE;


    if( ki.lenuser == 0 ) {
        aktool_error(_("user or subscriber's name is undefined, use \"--id\" option" ));
        return exitcode;
    }

    if( strlen( ki.key_file ) == 0 ) {
        aktool_error(_("the file with subscriber's key is undefined, use \"--key\" option" ));
        return exitcode;
    }

    if( ki.target_undefined == ak_false ) {
        if( ki.oid_of_target == NULL ) {
            aktool_error(_("the target cryptographic algorithm for pairwise key is undefined,"
                           " use \"--target\" option" ));
            return exitcode;
        }
        switch( ki.oid_of_target->engine ) {
            case block_cipher:
            case hmac_function:
            case sign_function:
                break;

            default:
                aktool_error(_("an engine of the given target cryptographic"
                               " algorithm is not supported (%s)" ),
                             ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
                return exitcode;
        }
    }


    if( !ki.quiet ) printf(_("loading subscriber's key: %s\n"), ki.key_file );
    if( ki.leninpass == 0 ) {
        if(( ki.leninpass = aktool_load_user_password( NULL, ki.inpass, sizeof( ki.inpass ), 0 )) < 1 )
        {
            aktool_error(_("incorrect password reading"));
            return exitcode;
        }
    }

    if( ak_blomkey_import_from_file_with_password( &abonent,
                                                   ki.inpass, ki.leninpass, ki.key_file ) != ak_error_ok ) {
        aktool_error(_("incorrect loading an abonent key from %s file\n"), ki.key_file );
        return exitcode;
    }

    if( ki.verbose ) {
        if( strlen( ki.userid ) == (size_t) ki.lenuser )
            printf(_("generation a pairwise key for %s: "), ki.userid );
        else printf(_("generation a pairwise key for %s: "),
                    ak_ptr_to_hexstr( ki.userid, ki.lenuser, ak_false ));
        fflush( stdout );
    }
    if( ki.target_undefined == ak_true ) {
        struct file fs;
        ak_uint8 key[64];

        if( ak_blomkey_create_pairwise_key_as_ptr( &abonent,
                                                   ki.userid, ki.lenuser, key, abonent.count ) != ak_error_ok ) {
            aktool_error(_("wrong pairwise key generation"));
            goto labex1;
        }
        if( !ki.quiet ) printf(_("Ok\n\n"));
        if( strlen( ki.os_file ) == 0 ) aktool_key_new_blom_pairwise_keyname();
        if( ak_file_create_to_write( &fs, ki.os_file ) != ak_error_ok ) {
            aktool_error(_("incorrect key file creation"));
            goto labex1;
        }
        if( ak_file_write( &fs, key, abonent.count ) != abonent.count ) {
            aktool_error(_("incorrect write to %s%s%s file"),
                         ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
        }
        else {
            if( !ki.quiet ) printf(_("secret key stored in %s%s%s file\n"),
                                   ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
            exitcode = EXIT_SUCCESS;
        }
        ak_file_close( &fs );
    }

    else {
        ak_pointer key = NULL;
        time_t now = time( NULL ), after = now + ki.days*86400;
        if(( key = ak_blomkey_new_pairwise_key( &abonent, ki.userid, ki.lenuser,
                                                ki.oid_of_target )) == NULL ) {
            aktool_error(_("wrong pairwise key generation"));
            goto labex1;
        }
        if( !ki.quiet ) printf(_("Ok\n\n"));
        if( ki.verbose ) printf(_("new key information:\n"));


        if( ki.keylabel != NULL ) {
            if( ki.verbose ) printf(_("label: %s\n"), ki.keylabel );
            ak_skey_set_label( (ak_skey)key, ki.keylabel, 0 );
        }


        if( ki.verbose ) {
            printf(_("resource: %lld "), (long long int)((ak_skey)key)->resource.value.counter );
            if( ((ak_skey)key)->resource.value.type == block_counter_resource ) printf(_("blocks\n"));
            else  printf(_("usages\n"));
            printf(_("not before: %s"), ctime( &now ));
            printf(_("not after: %s"), ctime( &after ));
        }
        if( ak_skey_set_validity( (ak_skey)key, now, after ) != ak_error_ok ) {
            aktool_error(_("incorrect assigning the validity of secret key"));
            goto labex1;
        }


        if( ki.lenoutpass == 0 ) {
            if(( ki.lenoutpass = aktool_load_user_password_twice( ki.outpass, sizeof( ki.outpass ))) < 1 )
                goto labex2;
        }


        if( ak_skey_export_to_file_with_password(
                key,
                ki.outpass,
                ki.lenoutpass,
                ki.os_file,
                ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
                ki.format
        ) != ak_error_ok ) aktool_error(_("wrong export a secret key to file %s%s%s"),
                                        ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
        else {
            if( !ki.quiet ) printf(_("secret key stored in %s%s%s file\n"),
                                   ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
            exitcode = EXIT_SUCCESS;
        }
        labex2: ak_oid_delete_object( ki.oid_of_target, key );
    }

    labex1:
    ak_blomkey_destroy( &abonent );

    return exitcode;
}

int aktool_key_new_keypair1( bool_t create_pair )
{
    time_interval_t tm;
    ak_pointer key = NULL;
    int exitcode = EXIT_FAILURE;

    /* 1. создаем ключ */
    if(( key = ak_oid_new_object( ki.oid_of_target )) == NULL ) return exitcode;

    /* 2. для асимметричных ключей устанавливаем кривую */
    if( ki.oid_of_target->engine == sign_function ) {
        if( ki.curve == NULL ) ki.curve = ak_oid_find_by_name( "cspa" );
        if( ak_signkey_set_curve( key, ki.curve->data ) != ak_error_ok ) {
            aktool_error(_("using non applicable elliptic curve (%s)"), ki.curve->name[0] );
            goto labex2;
        }
    }

    /* 3. вырабатываем случайный секретный ключ */
    if( ki.oid_of_target->func.first.set_key_random( key, ki.generator ) != ak_error_ok ) {
        aktool_error(_("incorrect creation of a random secret key value"));
        goto labex2;
    }

    /* 4. устанавливаем срок действия, в сутках, начиная с текущего момента */
    tm.not_before = time( NULL );
    tm.not_after = tm.not_before + ki.days*86400;
    if( ak_skey_set_validity( key, tm.not_before, tm.not_after ) != ak_error_ok ) {
        aktool_error(_("incorrect assigning the validity of secret key"));
        goto labex2;
    }

    /* 5. устанавливаем метку */
    if( ki.keylabel != NULL ) {
        if( ak_skey_set_label( key, ki.keylabel, strlen( ki.keylabel )) != ak_error_ok ) {
            aktool_error(_("incorrect assigning the label of secret key"));
            goto labex2;
        }
    }

    /* 6. если указано, то устанавливаем номер секретного ключа */
    if( ((ak_uint64 *)ki.cert.opts.ext_secret_key_number.number)[0] != 0 ) {
        memcpy( ((ak_skey)key)->number, ki.cert.opts.ext_secret_key_number.number,
                ak_min( sizeof( ki.cert.opts.ext_secret_key_number.number ),
                        sizeof( ((ak_skey)key)->number )));
    }

    /* 7. переходим к открытому ключу */
    if( create_pair ) {

        /* 7.1. вырабатываем открытый ключ,
           это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
        if( ak_verifykey_create_from_signkey( &ki.cert.vkey, key ) != ak_error_ok ) {
            aktool_error(_("incorrect creation of public key"));
            goto labex2;
        }

        /* 7.2. создаем обобщенное имя владельца ключей */
        ki.cert.opts.subject = aktool_key_input_name1();

        /* 7.3. */
        if( ki.format == aktool_magic_number ) {
            /* сохраняем открытый ключ как корневой сертификат и, в начале
               возвращаем необходимое значение формата выходных данных */
            ki.format = asn1_pem_format;
            /* устанавливаем срок действия сертификата */
            ki.cert.opts.time = tm;
            /* при использовании опции --secret-key-number добавляем номер секретного ключа */
            if( ki.cert.opts.ext_secret_key_number.is_present )
                memcpy( ki.cert.opts.ext_secret_key_number.number, ((ak_skey)key)->number,
                        ak_min( sizeof( ki.cert.opts.ext_secret_key_number.number ),
                                sizeof( ((ak_skey)key)->number )));
            /* сохраняем сертификат */
            if( ak_certificate_export_to_file( &ki.cert, key, &ki.cert, ki.generator,
                                               ki.op_file, ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ),
                                               ki.format ) != ak_error_ok ) {
                aktool_error(_("wrong export a public key to certificate %s%s%s"),
                             ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
                goto labex2;
            }
            else {
                if( !ki.quiet ) printf(_("certificate of public key stored in %s%s%s file\n"),
                                       ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
            }

            ak_certificate_destroy( &ki.cert );
        }
        else { /* сохраняем запрос на сертификат */
            if( ak_request_export_to_file( (ak_request)( &ki.cert ), key, ki.generator, ki.op_file,
                                           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
                aktool_error(_("wrong export a public key to request %s%s%s"),
                             ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
                goto labex2;
            } else {
                if( !ki.quiet )
                    printf(_("public key stored in %s%s%s file as certificate's request\n"),
                           ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
            }

            ak_request_destroy( (ak_request)( &ki.cert ));
        }
    } /* конец create_pair */

    /* восстанавливаем значение формата выходого файла */
    if( ki.format == aktool_magic_number ) ki.format = asn1_pem_format;

    /* 7. мастерим пароль для сохранения секретного ключа */
    if( ki.no_outpass ) {
        ki.lenoutpass = 0;
        memset( ki.outpass, 0, aktool_password_max_length );
    }
    else { /* если пароль не задан, то считываем его с консоли */
        if( ki.lenoutpass == 0 ) {
            if(( ki.lenoutpass =
                         aktool_load_user_password_twice( ki.outpass, sizeof( ki.outpass ))) < 1 ) {
                exitcode = EXIT_FAILURE;
                goto labex2;
            }
        }
    }

    /* 8. сохраняем созданный ключ в файле */
    if( ak_skey_export_to_file_with_password(
            key,            /* ключ */
            ki.outpass,     /* пароль */
            ki.lenoutpass,  /* длина пароля */
            ki.os_file,     /* если имя не задано,
                     то получаем новое имя файла */
            ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
            ki.format
    ) != ak_error_ok ) {
        aktool_error(_("wrong export a secret key to file %s%s%s"),
                     ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
        exitcode = EXIT_FAILURE;
        goto labex2;
    } else {
        /* секретный ключ хорошо хранить в хранилище, а не в файле */
        if( !ki.quiet ) printf(_("secret key stored in %s%s%s file\n"),
                               ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
        /* выводим информацию о созданном ключе */
        if( ki.verbose ) {
            if( ki.show_caption ) printf(" ----- \n");
            aktool_key_show_key1( ki.os_file, show_all );
        }
        exitcode = EXIT_SUCCESS;
    }

    labex2:
    ak_oid_delete_object( ki.oid_of_target, key );

    return exitcode;
}

static int aktool_key_input_name_from_console_line1( ak_tlv tlv, const char *sh, const char *lg  )
{
    size_t len = 0;
    char string[256];
    char *ptr = NULL;
    int error = ak_error_not_ready;

    if(( ptr = strstr( ki.userid, sh )) != NULL ) {
        ptr+=4; /* мы предполагаем, что на вход подается /xx= */
        len = 0;
        while( len < strlen( ptr )) {
            if( ptr[len]   == '/') break;
            ++len;
        }
        if( len > 0 ) {
            memset( string, 0, sizeof( string ));
            memcpy( string, ptr, ak_min( len, sizeof( string ) -1));
            error = ak_tlv_add_string_to_global_name( tlv, lg, string );
        }
    }

    return error;
}

int aktool_key_input_name_from_console1( ak_tlv subject )
{
    int error = ak_error_ok, found = ak_false;

    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/em=", "email-address" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/cn=", "common-name" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/su=", "surname" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/ct=", "country-name" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/lt=", "locality-name" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/st=", "state-or-province-name" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/sa=", "street-address" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/or=", "organization" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/ou=", "organization-unit" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/sn=", "serial-number" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/gn=", "given-name" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/tl=", "title" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/ps=", "pseudonym" ) == ak_error_ok ) found = ak_true;
/* свое, родное ))) */
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/og=", "ogrn" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/oi=", "ogrnip" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/si=", "snils" ) == ak_error_ok ) found = ak_true;
    if( aktool_key_input_name_from_console_line1( subject,
                                                 "/in=", "inn" ) == ak_error_ok ) found = ak_true;
    if( !found ) {
        error = ak_tlv_add_string_to_global_name( subject, "common-name", ki. userid );
    }

    return error;
}

int aktool_key_show_key1( char *filename, what_show_t what )
{
    ak_skey skey = NULL;
    ak_pointer key = NULL;
#ifndef AK_HAVE_WINDOWS_H
    char output_buffer[256];
#endif

    /* 1. создаем контекст ключа (без считывания ключевой информации, только параметры) */
    if(( key = ak_skey_new_from_file( filename )) == NULL ) {
        aktool_error(_("wrong reading a key from %s file\n"), filename );
        return EXIT_FAILURE;
    }

    skey = (ak_skey)key;
    switch( what ) {
        case show_algoid:
            printf("%s\n", skey->oid->id[0] );
            break;
        case show_curveoid:
            if( skey->oid->engine == sign_function ) {
                ak_oid curvoid = ak_oid_find_by_data( skey->data );
                if( curvoid == NULL ) printf("( undefined )\n");
                else printf("%s\n", curvoid->id[0] );
            }
            else printf("( undefined )\n");
            break;
        case show_number:
            printf("%s\n", ak_ptr_to_hexstr( skey->number, 32, ak_false ));
            break;
        case show_public_key:
            if( skey->oid->engine == sign_function ) {
                printf("%s\n", ak_ptr_to_hexstr(((ak_signkey)skey)->verifykey_number, 32, ak_false ));
            }
            else printf("( undefined )\n");
            break;
        case show_resource:
            printf("%ld\n", (long int)( skey->resource.value.counter ));
            break;
        case show_label:
            if( skey->label != NULL ) printf( "%s\n", skey->label );
            break;

        case show_all:
            printf(_("Type:\n"));
            if( skey->oid->engine == sign_function ) printf(_("    Asymmetric secret key\n"));
            else printf(_("    Symmetric secret key\n"));
            printf(_("Algorithm:\n    %s (%s, %s)\n"), ak_libakrypt_get_engine_name( skey->oid->engine ),
                   skey->oid->name[0], skey->oid->id[0] );
            printf(_("Number:\n    %s\n"), ak_ptr_to_hexstr( skey->number, 32, ak_false ));
            printf(_("Resource: %ld (%s)\n"), (long int)( skey->resource.value.counter ),
                   ak_libakrypt_get_counter_resource_name( skey->resource.value.type ));
#ifdef AK_HAVE_WINDOWS_H
            printf(_(" from: %s"), ctime( &skey->resource.time.not_before ));
      printf(_("   to: %s"), ctime( &skey->resource.time.not_after ));
#else
            strftime( output_buffer, sizeof( output_buffer ), /* локализованный вывод */
                      "%e %b %Y %H:%M:%S (%A) %Z", localtime( &skey->resource.time.not_before ));
            printf(_(" from: %s\n"), output_buffer );
            strftime( output_buffer, sizeof( output_buffer ), /* локализованный вывод */
                      "%e %b %Y %H:%M:%S (%A) %Z", localtime( &skey->resource.time.not_after ));
            printf(_("   to: %s\n"), output_buffer );
#endif

            /* для асимметричных секретных ключей выводим дополнительную информацию */
            if( skey->oid->engine == sign_function ) {
                ak_uint8 zerobuf[32];
                ak_oid curvoid = ak_oid_find_by_data( skey->data );

                printf(_("Public key number:\n    "));
                memset( zerobuf, 0, sizeof( zerobuf ));
                if( memcmp( zerobuf, ((ak_signkey)skey)->verifykey_number, 32 ) == 0 )
                    printf(_("( undefined )\n"));
                else printf("%s\n", ak_ptr_to_hexstr(((ak_signkey)skey)->verifykey_number, 32, ak_false ));

                printf(_("Curve:\n    "));
                if( curvoid == NULL ) printf(_("( undefined )\n"));
                else printf("%s (%s)\n", curvoid->name[0], curvoid->id[0] );
            }
            if( skey->label != NULL ) printf(_("Label:\n    %s\n"), skey->label );
            break;
    }
    ak_oid_delete_object( ((ak_skey)key)->oid, key );

    return EXIT_SUCCESS;
}

ak_tlv aktool_key_input_name1( void )
{
    size_t len = 0;
    ak_tlv subject;
    char string[256];
    bool_t noname = ak_true;

    /* a. При необходимости, создаем subject */
    if(( subject = ak_tlv_new_sequence()) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__,
                          "incorrect creation of tlv context for owner's common name" );
        return NULL;
    }

    /* b. Проверяем, задана ли строка с расширенным именем владельца */
    if( ki.lenuser > 0 ) {
        if( aktool_key_input_name_from_console1( subject ) != ak_error_ok )
            ak_error_message_fmt( ak_error_get_value(), __func__,
                                  "value of --id=%s option is'nt correct", ki.userid );
        return subject;
    }

    /* c. Выводим стандартное пояснение */
    if( ki.show_caption ) printf(" ----- \n");
    printf(_(
                   " You are about to be asked to enter information that will be incorporated\n"
                   " into your certificate request.\n"
                   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
                   " There are quite a few fields but you can leave some blank.\n"
                   " For some fields there will be a default value.\n"
                   " If you do not want to provide information just enter a string of one or more spaces.\n"));
    if( ki.show_caption ) printf(" ----- \n");

    /* Вводим расширенное имя с клавиатуры
       1. Country Name */

    ak_snprintf( string, len = sizeof( string ), "RU" );
    if( ak_string_read(_(" Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
#ifdef AK_HAVE_CTYPE_H
        string[0] = toupper( string[0] );
        string[1] = toupper( string[1] );
#endif
        string[2] = 0;
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "country-name", string ) == ak_error_ok )) noname = ak_false;
    }
    /* 2. State or Province */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" State or Province"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "state-or-province-name", string ) == ak_error_ok )) noname = ak_false;
    /* 3. Locality */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Locality (eg, city)"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "locality-name", string ) == ak_error_ok )) noname = ak_false;
    /* 4. Organization */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Organization (eg, company)"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "organization", string ) == ak_error_ok )) noname = ak_false;
    /* 5. Organization Unit*/
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Organization Unit"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "organization-unit", string ) == ak_error_ok )) noname = ak_false;
    /* 6. Street Address */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Street Address"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "street-address", string ) == ak_error_ok )) noname = ak_false;
    /* 7. Common Name */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Common Name"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "common-name", string ) == ak_error_ok )) noname = ak_false;
    /* 8. email address */
    memset( string, 0, len = sizeof( string ));
    if( ak_string_read(_(" Email Address"), string, &len ) == ak_error_ok )
        if( len && ( ak_tlv_add_string_to_global_name( subject,
                                                       "email-address", string ) == ak_error_ok )) noname = ak_false;
    if( ki.show_caption ) printf(" ----- \n");
    if( noname ) {
        aktool_error(
                _("generation of a secret or public keys without any information about owner are not allowed"));
    }

    return subject;
}


