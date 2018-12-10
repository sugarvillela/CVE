/*
  This file contains excerpts from three versions of linux of the implementation
  of join_session_keyring(), found in security/keys/process_keys.c. These 
  excerpts track the evolution of the bug and the fix.
  
  At the very bottom of the page, I include the function find_keyring_by_name().
  That function is called by join_session_keyring() to search for an existing
  key instance.  What is important is that find_keyring_by_name() increments
  the usage count in the key object, no matter what happens in the if-else 
  cases below. This is the root cause of the bug, and remains in the Kernel 
  code today
*/
/*===========================================================================*/
  Original Code, pre-3.8: note that there are two cases in the if-else
/*===========================================================================*/

/*
 * Join the named keyring as the session keyring if possible else attempt to
 * create a new one of that name and join that.
 *
 * If the name is NULL, an empty anonymous keyring will be installed as the
 * session keyring.
 *
 * Named session keyrings are joined with a semaphore held to prevent the
 * keyrings from going away whilst the attempt is made to going them and also
 * to prevent a race in creating compatible session keyrings.
 */
long join_session_keyring(const char *name)
{
	const struct cred *old;
	struct cred *new;
	struct key *keyring;
	long ret, serial;

	/* only permit this if there's a single thread in the thread group -
	 * this avoids us having to adjust the creds on all threads and risking
	 * ENOMEM */
	if (!current_is_single_threaded())
		return -EMLINK;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	/* if no name is provided, install an anonymous keyring */
	if (!name) {
		ret = install_session_keyring_to_cred(new, NULL);
		if (ret < 0)
			goto error;

		serial = new->tgcred->session_keyring->serial;
		ret = commit_creds(new);
		if (ret == 0)
			ret = serial;
		goto okay;
	}

	/* allow the user to join or create a named keyring */
	mutex_lock(&key_session_mutex);

	/* look for an existing keyring of this name */
	keyring = find_keyring_by_name(name, false);
	if (PTR_ERR(keyring) == -ENOKEY) {
		/* not found - try and create a new one */
		keyring = keyring_alloc(name, old->uid, old->gid, old,
					KEY_ALLOC_IN_QUOTA, NULL);
		if (IS_ERR(keyring)) {
			ret = PTR_ERR(keyring);
			goto error2;
		}
	} else if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto error2;
	}

	/* we've got a keyring - now to install it */
	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0)
		goto error2;

	commit_creds(new);
	mutex_unlock(&key_session_mutex);

	ret = keyring->serial;
	key_put(keyring);
okay:
	return ret;

error2:
	mutex_unlock(&key_session_mutex);
error:
	abort_creds(new);
	return ret;
}

/*===========================================================================*/
  Changed Code, Version 3.8 through 3.17: note that there are now three cases 
  in the if-else.  The third case handles requests by duplicate keys simply by
  aborting. However the usage count is always incremented, even on abort.
/*===========================================================================*/

long join_session_keyring(const char *name)
{
	const struct cred *old;
	struct cred *new;
	struct key *keyring;
	long ret, serial;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	/* if no name is provided, install an anonymous keyring */
	if (!name) {
		ret = install_session_keyring_to_cred(new, NULL);
		if (ret < 0)
			goto error;

		serial = new->session_keyring->serial;
		ret = commit_creds(new);
		if (ret == 0)
			ret = serial;
		goto okay;
	}

	/* allow the user to join or create a named keyring */
	mutex_lock(&key_session_mutex);

	/* look for an existing keyring of this name */
	keyring = find_keyring_by_name(name, false);
	if (PTR_ERR(keyring) == -ENOKEY) {
		/* not found - try and create a new one */
		keyring = keyring_alloc(
			name, old->uid, old->gid, old,
			KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK,
			KEY_ALLOC_IN_QUOTA, NULL);
		if (IS_ERR(keyring)) {
			ret = PTR_ERR(keyring);
			goto error2;
		}
	} else if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto error2;
	} else if (keyring == new->session_keyring) {
		ret = 0;
		goto error2;
	}

	/* we've got a keyring - now to install it */
	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0)
		goto error2;

	commit_creds(new);
	mutex_unlock(&key_session_mutex);

	ret = keyring->serial;
	key_put(keyring);
okay:
	return ret;

error2:
	mutex_unlock(&key_session_mutex);
error:
	abort_creds(new);
	return ret;
}

/*===========================================================================*/
  'Fixed' Code, post 3.18: Some fixes add a 'put' command in the third case, so
  that the duplicate key is added...if that is the solution, why have the third
  case at all?  This version adds a third error path, calling 'put' at that 
  point.  None of it really makes sense, but the bug is fixed.
/*===========================================================================*/

long join_session_keyring(const char *name)
{
	const struct cred *old;
	struct cred *new;
	struct key *keyring;
	long ret, serial;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	/* if no name is provided, install an anonymous keyring */
	if (!name) {
		ret = install_session_keyring_to_cred(new, NULL);
		if (ret < 0)
			goto error;

		serial = new->session_keyring->serial;
		ret = commit_creds(new);
		if (ret == 0)
			ret = serial;
		goto okay;
	}

	/* allow the user to join or create a named keyring */
	mutex_lock(&key_session_mutex);

	/* look for an existing keyring of this name */
	keyring = find_keyring_by_name(name, false);
	if (PTR_ERR(keyring) == -ENOKEY) {
		/* not found - try and create a new one */
		keyring = keyring_alloc(
			name, old->uid, old->gid, old,
			KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK,
			KEY_ALLOC_IN_QUOTA, NULL, NULL);
		if (IS_ERR(keyring)) {
			ret = PTR_ERR(keyring);
			goto error2;
		}
	} else if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto error2;
	} else if (keyring == new->session_keyring) {
		ret = 0;
		goto error3;
	}

	/* we've got a keyring - now to install it */
	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0)
		goto error3;

	commit_creds(new);
	mutex_unlock(&key_session_mutex);

	ret = keyring->serial;
	key_put(keyring);
okay:
	return ret;

error3:
	key_put(keyring);
error2:
	mutex_unlock(&key_session_mutex);
error:
	abort_creds(new);
	return ret;
}

/*===========================================================================*/
  find_keyring_by_name is found in security/keys/keyring.c.
  It increments the usage count any time it finds a key.
/*===========================================================================*/

/*
 * Find a keyring with the specified name.
 *
 * All named keyrings in the current user namespace are searched, provided they
 * grant Search permission directly to the caller (unless this check is
 * skipped).  Keyrings whose usage points have reached zero or who have been
 * revoked are skipped.
 *
 * Returns a pointer to the keyring with the keyring's refcount having being
 * incremented on success.  -ENOKEY is returned if a key could not be found.
 */
struct key *find_keyring_by_name(const char *name, bool skip_perm_check)
{
	struct key *keyring;
	int bucket;

	if (!name)
		return ERR_PTR(-EINVAL);

	bucket = keyring_hash(name);

	read_lock(&keyring_name_lock);

	if (keyring_name_hash[bucket].next) {
		/* search this hash bucket for a keyring with a matching name
		 * that's readable and that hasn't been revoked */
		list_for_each_entry(keyring,
				    &keyring_name_hash[bucket],
				    type_data.link
				    ) {
			if (!kuid_has_mapping(current_user_ns(), keyring->user->uid))
				continue;

			if (test_bit(KEY_FLAG_REVOKED, &keyring->flags))
				continue;

			if (strcmp(keyring->description, name) != 0)
				continue;

			if (!skip_perm_check &&
			    key_permission(make_key_ref(keyring, 0),
					   KEY_NEED_SEARCH) < 0)
				continue;

			/* we've got a match but we might end up racing with
			 * key_cleanup() if the keyring is currently 'dead'
			 * (ie. it has a zero usage count) */
			if (!atomic_inc_not_zero(&keyring->usage))
				continue;
			keyring->last_used_at = current_kernel_time().tv_sec;
			goto out;
		}
	}

	keyring = ERR_PTR(-ENOKEY);
out:
	read_unlock(&keyring_name_lock);
	return keyring;
}
