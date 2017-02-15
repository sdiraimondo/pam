#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <shadow.h>
#include <regex.h>
#include <sys/stat.h>

/* Define which PAM interfaces we provide */
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define SSHWARN "/run/sshwarn"
  
/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct stat sbuf;
	struct spwd *sp;
	FILE *fp;
	char *linebuf = NULL;
	size_t nchars;
	regex_t pwregex;

	// default is no warning, so delete the flag file if it exists
	if (stat (SSHWARN, &sbuf) == 0) unlink (SSHWARN);

	// is SSH enabled?
	if (stat ("/run/sshd.pid", &sbuf) == -1) return PAM_IGNORE;

	// is password authentication for SSH enabled?
	fp = fopen ("/etc/ssh/sshd_config", "r");
	if (fp)
	{
		regcomp (&pwregex, "^PasswordAuthentication\\s*no", REG_EXTENDED);
		while (getline (&linebuf, &nchars, fp) != -1)
		{
			if (!regexec (&pwregex, linebuf, 0, NULL, 0))
			{
				free (linebuf);
				fclose (fp);
				return PAM_IGNORE;
			}
		}
		free (linebuf);
		fclose (fp);
	}

	// get the pi user entry from the shadow file
	setspent ();
	sp = getspnam ("pi");
	endspent ();

	if (sp && sp->sp_pwdp)
	{
		// there is a properly-formatted entry in the shadow file - check the password
		char *enc = crypt ("raspberry", sp->sp_pwdp);

		if (enc && !strcmp (sp->sp_pwdp, enc))
		{
			// password match - create the flag file
			fp = fopen (SSHWARN, "wb");
			fclose (fp);
		}
	}

	return PAM_IGNORE;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

struct pam_module _pam_chksshpwd_modstruct =
{
	"pam_chksshpwd",
	NULL,
	NULL,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL,
};

#endif
