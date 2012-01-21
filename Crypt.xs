/*
 ===========================================================================
 Module::Crypt

 Encrypt your Perl code and compile it into XS
 
 Author: Alessandro Ranellucci <aar@cpan.org>
 Copyright (c).
 
 This is EXPERIMENTAL code. Use it AT YOUR OWN RISK.
 ===========================================================================
*/

/* If you're looking at this code, please note that I'm not */
/* a C coder. That's why the following code works but is  */
/* probably bad. Any contribution from more experienced C */
/* programmers is very welcome. */


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <EXTERN.h>
#include <perl.h>
#include <stdlib.h>
#include <string.h>



#define SIZE 4096

static char * text;
static const char my_name[] = "Module::Crypt";
static const char author[] = "Alessandro Ranellucci <aar@cpan.org>";
static const char cpright[] = "Copyright (c) 2005";



/**
 * 'Alleged RC4' Source Code picked up from the news.
 * From: allen@gateway.grumman.com (John L. Allen)
 * Newsgroups: comp.lang.c
 * Subject: Shrink this C code for fame and fun
 * Date: 21 May 1996 10:49:37 -0400
 */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte. 
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void arc4(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

unsigned rand_mod(unsigned mod)
{
	/* Without skew */
	unsigned rnd, top = RAND_MAX;
	top -= top % mod;
	while (top <= (rnd = rand()))
		continue;
	/* Using high-order bits. */
	rnd = 1.0*mod*rnd/(1.0+top);
	return rnd;
}

char rand_chr(void)
{
	return (char)rand_mod(1<<(sizeof(char)<<3));
}

int noise(char * ptr, unsigned min, unsigned xtra, int str)
{
	if (xtra) xtra = rand_mod(xtra);
	xtra += min;
	for (min = 0; min < xtra; min++, ptr++)
		do
			*ptr = rand_chr();
		while (str && !isalnum((int)*ptr));
	if (str) *ptr = '\0';
	return xtra;
}

static int offset;

void prnt_bytes(char* o, char * ptr, int m, int l, int n)
{
	int i;
	
	l += m;
	n += l;
	for (i = 0; i < n; i++) {
		if ((i & 0xf) == 0)
			strcat(o, "\n\t\"");
		sprintf(o, "%s\\%03o", o, (unsigned char)((i>=m) && (i<l) ? ptr[i-m] : rand_chr()));
		if ((i & 0xf) == 0xf)
			strcat(o, "\"");
	}
	if ((i & 0xf) != 0)
		strcat(o, "\"");
	offset += n;
}

void prnt_array(char* o, void * ptr, char * name, int l, char * cast)
{
	int m = rand_mod(1+l/4);		/* Random amount of random pre  padding (offset) */
	int n = rand_mod(1+l/4);		/* Random amount of random post padding  (tail)  */
	int a = (offset+m)%l;
	if (cast && a) m += l - a;		/* Type alignement. */
	
	char tmpop[1000];
	
	strcat(o, "\n");
	
	sprintf(tmpop, "#define      %s_z	%d", name, l);
	strcat(o, tmpop);
	
	strcat(o, "\n");
	
	sprintf(tmpop, "#define      %s	(%s(&data[%d]))", name, cast?cast:"", offset+m);
	strcat(o, tmpop);
	prnt_bytes(o, ptr, m, l, n);
}

void read_script (SV* script)
{
		STRLEN len;
		char* mytext = SvPV(script, len);
		int l;
		l = strlen(mytext);
		
		text = malloc(l + SIZE);
		strcpy(text, mytext);
		text = realloc(text, l + SIZE + 1);
		text[l] = '\0';
}


MODULE = Module::Crypt		PACKAGE = Module::Crypt
	
SV *
wr(SV* script)
	PROTOTYPE: $
	CODE:
	read_script(script);
	
	char pswd[256];
	int pswd_z = sizeof(pswd);
	int text_z = strlen(text) + 1;
	
	int indx;
	int numd = 0;
	int done = 0;
	
	/* Encrypt */
	srand((unsigned)time(NULL)^(unsigned)getpid());
	pswd_z = noise(pswd, pswd_z, 0, 0); numd++;
	stte_0();
	 key(pswd, pswd_z);
	arc4(text, text_z); numd++;
	
	/* Output */
	char* o = malloc(strlen(text) + strlen(text)*24 + SIZE);  /* UGLY HACK -- patches welcome */
	o[0]='\0';
	
	strcat(o, "static  char data [] = ");
	
	do {
		done = 0;
		indx = rand_mod(1);
		do {
			switch (indx) {
			case  0: if (pswd_z>=0) {prnt_array(o, pswd, "pswd", pswd_z, 0); pswd_z=done=-1; break;}
			case  1: if (text_z>=0) {prnt_array(o, text, "text", text_z, 0); text_z=done=-1; break;}
			}
			indx = 0;
		} while (!done);
	} while (numd+=done);
	
	strcat(o, "/* End of data[] */;\n");
	
	RETVAL = newSVpv(o, 0);
	
	OUTPUT:
		RETVAL
		