#include <stdio.h>
#include <string.h>
#include <crypt.h>

/* Define which PAM interfaces we provide */
  #define PAM_SM_SESSION

  /* Include PAM headers */
  #include <security/pam_appl.h>
  #include <security/pam_modules.h>
  
  
/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	char buf[1024], *salt;
	FILE *fp;

	// default is no warning, so delete the flag file
	system ("rm /var/lib/chksshpwd/sshwarn");

	// is SSH enabled?
	if ((fp = popen ("/usr/sbin/service ssh status | grep -q running", "r")) == NULL) return PAM_IGNORE;
	if (pclose (fp)) return PAM_IGNORE;

	// is password authentication for SSH enabled?
	if ((fp = popen ("grep -q '^PasswordAuthentication\\s*no' /etc/ssh/sshd_config", "r")) == NULL) return PAM_IGNORE;
	if (!pclose (fp)) return PAM_IGNORE;

	// get the pi user line from the shadow file
    if ((fp = popen ("grep -E ^pi: /etc/shadow", "r")) == NULL) return PAM_IGNORE;
    fgets (buf, sizeof (buf) - 1, fp);
    if (pclose (fp)) return PAM_IGNORE;

    // check for locked password, password disabled, strange ciphers etc - all indicate a change
    if (!strncmp (buf, "pi:$", 4))
 	{
		// password file entry as expected - check the password itself
		salt = buf + 3;
		strtok (salt, ":");
		if (!strcmp (salt, crypt ("raspberry", salt)))
		{
		    fp = fopen ("/var/lib/chksshpwd/sshwarn", "wb");
		    fclose (fp);
		}
	}

	return PAM_IGNORE;
}

  /* PAM entry point for session cleanup */
  int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return PAM_IGNORE;
  }
