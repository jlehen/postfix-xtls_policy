/*++
/* NAME
/*	tls_verify 3
/* SUMMARY
/*	peer name and peer certificate verification
/* SYNOPSIS
/*	#define TLS_INTERNAL
/*	#include <tls.h>
/*
/*	char *tls_peer_CN(peercert)
/*	X509   *peercert;
/*
/*	char *tls_issuer_CN(peercert)
/*	X509   *peercert;
/*
/*	char *tls_peer_DN(peercert)
/*	X509   *peercert;
/*
/*	char *tls_issuer_DN(peercert)
/*	X509   *peercert;
/*
/*	long tls_serial_number(peercert)
/*	X509   *peercert;
/*
/*	long tls_emails(peercert)
/*	X509   *peercert;
/*
/*	int	tls_verify_certificate_callback(ok, ctx)
/*	int	ok;
/*	X509_STORE_CTX *ctx;
/* DESCRIPTION
/*	tls_peer_CN() returns the text CommonName for the peer
/*	certificate subject, or a null pointer if no CommonName was
/*	found. The result is allocated with mymalloc() and must be
/*	freed by the caller.
/*
/*	tls_issuer_CN() returns the text CommonName for the peer
/*	certificate issuer, or a null pointer if no CommonName was
/*	found. The result is allocated with mymalloc() and must be
/*	freed by the caller.
/*
/*	tls_peer_DN() returns the full text for the peer
/*	certificate subject, or a null pointer if no CommonName was
/*	found. The result is allocated with mymalloc() and must be
/*	freed by the caller.
/*
/*	tls_issuer_DN() returns the full text for the peer
/*	certificate issuer, or a null pointer if no CommonName was
/*	found. The result is allocated with mymalloc() and must be
/*	freed by the caller.
/*
/*	tls_serial_number() returns the serial number of the peer 
/*	certificate, or a null pointer if there was insufficient
/*	memory. The result is allocated with mymalloc() and must be
/*	freed by the caller.
/*
/*	tls_emails() returns a comma-separated list of e-mail addresses
/*	contained in either the subject or subjectAltName X509
/*	extension, or a null pointer if there was no address or
/*	insufficient memory for OpenSSL. The result is allocated with
/*	mymalloc() and must be freebsd bu the caller.
/*
/*	tls_verify_callback() is called several times (directly or
/*	indirectly) from crypto/x509/x509_vfy.c. It is called as
/*	a final check, and if it returns "0", the handshake is
/*	immediately shut down and the connection fails.
/*
/*	Postfix/TLS has two modes, the "opportunistic" mode and
/*	the "enforce" mode:
/*
/*	In the "opportunistic" mode we never want the connection
/*	to fail just because there is something wrong with the
/*	peer's certificate. After all, we would have sent or received
/*	the mail even if TLS weren't available.  Therefore the
/*	return value is always "1".
/*
/*	The SMTP client or server may require TLS (e.g. to protect
/*	passwords), while peer certificates are optional.  In this
/*	case we must return "1" even when we are unhappy with the
/*	peer certificate.  Only when peer certificates are required,
/*      certificate verification failure will result in immediate
/*	termination (return 0).
/*
/*	The only error condition not handled inside the OpenSSL
/*	library is the case of a too-long certificate chain. We
/*	test for this condition only if "ok = 1", that is, if
/*	verification didn't fail because of some earlier problem.
/*
/*	Arguments:
/* .IP ok
/*	Result of prior verification: non-zero means success.  In
/*	order to reduce the noise level, some tests or error reports
/*	are disabled when verification failed because of some
/*	earlier problem.
/* .IP ctx
/*	TLS client or server context. This also specifies the
/*	TLScontext with enforcement options.
/* DIAGNOSTICS
/*	tls_peer_CN() and tls_issuer_CN() log a warning and return
/*	a null pointer when 1) the requested information is not
/*	available in the specified certificate, 2) the result
/*	exceeds a fixed limit, or 3) the result contains null
/*	characters.
/* LICENSE
/* .ad
/* .fi
/*	This software is free. You can do with it whatever you want.
/*	The original author kindly requests that you acknowledge
/*	the use of his software.
/* AUTHOR(S)
/*	Originally written by:
/*	Lutz Jaenicke
/*	BTU Cottbus
/*	Allgemeine Elektrotechnik
/*	Universitaetsplatz 3-4
/*	D-03044 Cottbus, Germany
/*
/*	Updated by:
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>

#ifdef USE_TLS
#include <string.h>

/* Utility library. */

#include <msg.h>
#include <mymalloc.h>

/* TLS library. */

#define TLS_INTERNAL
#include <tls.h>

/* tls_verify_certificate_callback - verify peer certificate info */

int     tls_verify_certificate_callback(int ok, X509_STORE_CTX *ctx)
{
    char    buf[1024];
    X509   *err_cert;
    int     err;
    int     depth;
    int     verify_depth;
    SSL    *con;
    TLScontext_t *TLScontext;

    /* Adapted from OpenSSL apps/s_cb.c */

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    con = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    TLScontext = SSL_get_ex_data(con, TLScontext_index);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
    if (TLScontext->log_level >= 2)
	msg_info("certificate verification depth=%d subject=%s", depth, buf);

    /*
     * Test for a too long certificate chain, because that error condition is
     * not handled by the OpenSSL library.
     */
    verify_depth = SSL_get_verify_depth(con);
    if (ok && (verify_depth >= 0) && (depth > verify_depth)) {
	ok = 0;
	err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	X509_STORE_CTX_set_error(ctx, err);
    }
    if (!ok) {
	msg_info("certificate verification failed for %s: num=%d:%s",
		 TLScontext->peername, err,
		 X509_verify_cert_error_string(err));
    }

    /*
     * We delay peername verification until the SSL handshake completes. The
     * peername verification previously done here is now called directly from
     * tls_client_start(). This substantially simplifies the cache interface.
     */

    /*
     * Other causes for verification failure.
     */
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
			  buf, sizeof(buf));
	msg_info("certificate verification failed for %s:"
		 "issuer %s certificate unavailable",
		 TLScontext->peername, buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	msg_info("certificate verification failed for %s:"
		 "certificate not yet valid",
		 TLScontext->peername);
	break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	msg_info("certificate verification failed for %s:"
		 "certificate has expired",
		 TLScontext->peername);
	break;
    }
    if (TLScontext->log_level >= 2)
	msg_info("verify return: %d", ok);

    /*
     * Never fail in case of opportunistic mode.
     */
    if (TLScontext->enforce_verify_errors)
	return (ok);
    else
	return (1);
}

/* tls_entry_to_utf8() - ... */

static char *tls_entry_to_utf8(X509_NAME_ENTRY *entry,
			       const char *label, const char *field)
{
    int     len;
    ASN1_STRING *entry_str;
    unsigned char *tmp;
    char   *fieldsep;
    char   *result;

    fieldsep = " ";
    if (field == 0) { 
	field = "";
	fieldsep = "";
    }

    if ((entry_str = X509_NAME_ENTRY_get_data(entry)) == 0) {
	/* This should not happen */
	msg_warn("error reading peer certificate %s%s%s data",
		 label, fieldsep, field);
	tls_print_errors();
	return (0);
    }

    if ((len = ASN1_STRING_to_UTF8(&tmp, entry_str)) < 0) {
	/* This should not happen */
	msg_warn("error decoding peer certificate %s%s%s data",
		 label, fieldsep, field);
	tls_print_errors();
	return (0);
    }

    /*
     * Since the peer CN is used in peer verification, take care to detect
     * truncation due to excessive length or internal NULs.
     */
    if (len >= CCERT_BUFSIZ) {
	OPENSSL_free(tmp);
	msg_warn("peer %s%s%s too long: %d", label, fieldsep, field, (int) len);
	return (0);
    }

    /*
     * Standard UTF8 does not encode NUL as 0b11000000, that is
     * a Java "feature". So we need to check for embedded NULs.
     */
    if (strlen((char *) tmp) != len) {
	msg_warn("internal NUL in peer %s%s%s", label, fieldsep, field);
	OPENSSL_free(tmp);
	return (0);
    }

    result = mystrdup((char *) tmp);
    OPENSSL_free(tmp);
    return (result);
}

#ifndef DONT_GRIPE
#define DONT_GRIPE 0
#define DO_GRIPE 1
#endif

/* tls_text_name - extract certificate property value by name */

static char *tls_text_name(X509_NAME *name, int nid, char *label, int gripe)
{
    int     pos;
    X509_NAME_ENTRY *entry;

    if (name == 0
    	|| (pos = X509_NAME_get_index_by_NID(name, nid, -1)) < 0) {
	if (gripe != DONT_GRIPE) {
	    msg_warn("peer certificate has no %s", label);
	    tls_print_errors();
	}
	return (0);
    }

#if 0
    /*
     * If the match is required unambiguous, insist that that no
     * other values be present.
     */
    if (unique == UNIQUE && X509_NAME_get_index_by_NID(name, nid, pos) >= 0) {
	msg_warn("multiple %ss in peer certificate", label);
	return (0);
    }
#endif

    if ((entry = X509_NAME_get_entry(name, pos)) == 0) {
	/* This should not happen */
	msg_warn("error reading peer certificate %s entry", label);
	tls_print_errors();
	return (0);
    }

    return (tls_entry_to_utf8(entry, label, 0));
}

/* Should handle most of existing subject/issuer names */
#ifndef CCERT_BIGBUFSIZ
#define CCERT_BIGBUFSIZ 2048
#endif

/* tls_text_fullname - ... */

static char *tls_text_fullname(X509_NAME *name, char *label)
{
    int     fieldcount;
    int     lastfield;
    int     i;
    char   *result;
    int     resultcount;	    /* Bytes left in the result buffer */
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *field;
    int     fldnid;
    const char *fldbuf;
    int     fldbuflen;
    char   *valbuf;
    int     valbuflen;

    result = mymalloc(CCERT_BIGBUFSIZ);
    *result = '\0';
    resultcount = CCERT_BIGBUFSIZ - 1;

    lastfield = 0;
    fieldcount = X509_NAME_entry_count(name);
    for (i = fieldcount - 1; i >= 0; i--) {
	entry = X509_NAME_get_entry(name, i);

	/* First get the field name */
	field = X509_NAME_ENTRY_get_object(entry);
	fldnid = OBJ_obj2nid(field);
	if (fldnid == NID_undef) {
	    msg_warn("unknown field name when decoding %s", label);
	    myfree(result);
	    return (0);
	}
	fldbuf = OBJ_nid2sn(fldnid);
	fldbuflen = (int) strlen(fldbuf);

	/* Then decode the field value */
	valbuf = tls_entry_to_utf8(entry, label, fldbuf);
	if (valbuf == 0) {
	    myfree(result);
	    return (0);
	}
	valbuflen = (int) strlen(valbuf);

	/* Add "field=value," to the result */
	lastfield = (i == 0) ? 1 : 0;
	if (fldbuflen + valbuflen + 1 + (lastfield ? 0 : 1) > resultcount) {
	    msg_warn("peer %s too long", label);
	    myfree(valbuf);
	    myfree(result);
	    return (0);
	}

	strcat(result, fldbuf);
	strcat(result, "=");
	strcat(result, valbuf);
	resultcount -= fldbuflen + 1 + valbuflen;
	if (!lastfield) {
	    strcat(result, ",");
	    resultcount--;
	}
	myfree(valbuf);
    }

    return (result);
}

/* tls_peer_CN - extract peer common name from certificate */

char   *tls_peer_CN(X509 *peercert)
{
    char   *cn;

    cn = tls_text_name(X509_get_subject_name(peercert),
		       NID_commonName, "subject CN", DO_GRIPE);
    return (cn);
}

/* tls_issuer_CN - extract issuer common name from certificate */

char   *tls_issuer_CN(X509 *peer)
{
    X509_NAME *name;
    char   *cn;

    name = X509_get_issuer_name(peer);

    /*
     * If no issuer CN field, use Organization instead. CA certs without a CN
     * are common, so we only complain if the organization is also missing.
     */
    if ((cn = tls_text_name(name, NID_commonName, "issuer CN", DONT_GRIPE)) == 0)
	cn = tls_text_name(name, NID_organizationName,
			   "issuer Organization", DO_GRIPE);
    return (cn);
}

/* tls_peer_DN - extract peer full name from certificate */

char   *tls_peer_DN(X509 *peer)
{
    char *subject;

    subject = tls_text_fullname(X509_get_subject_name(peer), "subject");
    return (subject);
}

/* tls_issuer_DN - extract issuer full name from certificate */

char   *tls_issuer_DN(X509 *peer)
{
    char *issuer;

    issuer = tls_text_fullname(X509_get_issuer_name(peer), "issuer");
    return (issuer);
}

/* tls_serial_number - extract certificate serial number */

char   *tls_serial_number(X509 *peer)
{
    ASN1_INTEGER *sn;
    BIGNUM bn;
    char *bnstr, *snstr;
    size_t len;

    if ((sn = X509_get_serialNumber(peer)) == 0)
	return (0);
    BN_init(&bn);
    ASN1_INTEGER_to_BN(sn, &bn);
    if ((bnstr = BN_bn2hex(&bn)) == NULL)
	msg_fatal("insufficient memory for bignum stringification: %m");
    snstr = mystrdup(bnstr);
    OPENSSL_free(bnstr);
    return (snstr);
}

/* 
 * tls_emails - extract e-mail addresses contained in either subject
 * or subjectAltName
 */

char   *tls_emails(X509 *peer)
{
    STACK *stack;
    size_t len;
    int i;
    char *result;

    stack = X509_get1_email(peer);
    if (M_sk_num(stack) <= 0)
	return (0);

    /*
     * Allocate the destination buffer.
     */
    for (len = 0, i = 0; i < M_sk_num(stack); i++)
	len += strlen(M_sk_value(stack, i)) + 2;
    len -= 1;
    result = mymalloc(len);	    /* Cannot fail. */

    /*
     * Concatenate all e-mail addresses, separated by commas.
     */
    result[0] = '\0';
    for (i = 0; i < M_sk_num(stack); i++) {
	strcat(result, M_sk_value(stack, i));
	if (i < M_sk_num(stack) - 1)
	    strcat(result, ", ");
	OPENSSL_free(M_sk_value(stack, i));
    }
    sk_free(stack);

    return result;
}


#endif
