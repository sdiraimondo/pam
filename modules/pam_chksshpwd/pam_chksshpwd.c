#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <shadow.h>
#include <sys/stat.h>

/* Define which PAM interfaces we provide */
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
  
/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct stat sbuf;
	struct spwd *sp;
	FILE *fp;

	// check directory exists; create it if not
	if (stat ("/run/chksshpwd", &sbuf)) mkdir ("/run/chksshpwd", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	// default is no warning, so delete the flag file if it exists
	if (!stat ("/run/chksshpwd/sshwarn", &sbuf)) unlink ("/run/chksshpwd/sshwarn");

	// is SSH enabled?
	if ((fp = popen ("/usr/bin/pgrep -cx -u root sshd > /dev/null", "r")) == NULL) return PAM_IGNORE;
	if (pclose (fp)) return PAM_IGNORE;

	// is password authentication for SSH enabled?
	if ((fp = popen ("/bin/grep -q '^PasswordAuthentication\\s*no' /etc/ssh/sshd_config", "r")) == NULL) return PAM_IGNORE;
	if (!pclose (fp)) return PAM_IGNORE;

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
			fp = fopen ("/run/chksshpwd/sshwarn", "wb");
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
