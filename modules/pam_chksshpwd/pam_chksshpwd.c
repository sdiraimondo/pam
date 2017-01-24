#include <stdio.h>
#include <string.h>
#include <crypt.h>

/* Define which PAM interfaces we provide */
  #define PAM_SM_ACCOUNT
  #define PAM_SM_AUTH
  #define PAM_SM_PASSWORD
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
	fp = popen ("/usr/sbin/service ssh status | grep -q running", "r");
	if (fp == NULL) return (PAM_SUCCESS);
	if (pclose (fp)) return (PAM_SUCCESS);

	// is password authentication for SSH enabled?
	fp = popen ("grep -q '^PasswordAuthentication\\s*no' /etc/ssh/sshd_config", "r");
	if (fp == NULL) return (PAM_SUCCESS);
	if (!pclose (fp)) return (PAM_SUCCESS);

	// get the pi user line from the shadow file
    fp = popen ("grep -E ^pi: /etc/shadow", "r");
	if (fp == NULL) return (PAM_SUCCESS);
    fgets (buf, sizeof (buf) - 1, fp);
    if (pclose (fp)) return (PAM_SUCCESS);

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
			 //system ("touch /home/pi/.sshwarn");
		}
	}

	return (PAM_SUCCESS);
}

  /* PAM entry point for session cleanup */
  int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_SUCCESS);
  }

  /* PAM entry point for accounting */
  int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_SUCCESS);
  }

  /* PAM entry point for authentication verification */
  int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_SUCCESS);
  }

  /*
     PAM entry point for setting user credentials (that is, to actually
     establish the authenticated user's credentials to the service provider)
   */
  int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_SUCCESS);
  }

  /* PAM entry point for authentication token (password) changes */
  int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_SUCCESS);
  }
