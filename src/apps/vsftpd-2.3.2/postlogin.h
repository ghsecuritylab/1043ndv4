#ifndef VSF_POSTLOGIN_H
#define VSF_POSTLOGIN_H

#define MAX_CURRENT_PATH_LEN 256
enum FTP_PERMISSION_VAL {
	FTP_NOT_ALLOW = 0, 	/*不允许访问*/
	FTP_READ_AND_WRITE, /*读写*/
	FTP_READ_ONLY		/*只读*/
};
struct vsf_session;
#define MAX_USER_NUM 4
/* process_post_login()
 * PURPOSE
 * Called to begin FTP protocol parsing for a logged in session.
 * PARAMETERS
 * p_sess       - the current session object
 */
void process_post_login(struct vsf_session* p_sess);

#endif /* VSF_POSTLOGIN_H */

