

#! /usr/bin/stap -gv

/* A systemtap emergency band-aid for CVE-2016-0728.
   fche@redhat.com & wmealing@redhat.com
*/


/* Default behavior: trace but don't fix problem. */ 
global trace_p = 1 /* or else:  stap -G trace_p=0 */
global fix_p = 0   /* or else:  stap -G fix_p=1 */


probe kernel.statement("join_session_keyring@*+44") !,
      kernel.function("join_session_keyring").label("error2")
{
  /* NB: if the DWARF debuginfo were more perfect, we should be able
     to refer directly to $keyring/$new, local variables still
     technically in scope.  On some kernels/gcc combinations, that
     works fine.  On others, it doesn't, so this script tries to 
     support both. */
  if (@defined($keyring))
    keyring = $keyring
  else {
    if (! warned_keyrings_p++)
      warn("Using find_keyring_by_name $return heuristic for $keyring")
    keyring = keyrings[tid()]
  }
  if (@defined($new))
    new = $new
  else {
    if (! warned_news_p++)
      warn("Using prepare_creds $return heuristic for $new")
    new = news[tid()]
  }

	/* The actual security band-aid payload. */
	if (keyring == @cast(new,"struct cred")->session_keyring) {
	    if (trace_p) 
		printf("%s[%d] rejoin keyring %s %p %s\n", execname(), tid(), $name$, keyring, @cast( keyring,"struct key" )->usage$$ );
	    if (fix_p) 
		do_key_put(keyring);
	    if (fix_p && trace_p) 
		printf("-> %p %s\n", keyring, @cast(keyring,"struct key")->usage$$ );
	}
}

function do_key_put(ptr)
%{
  if (STAP_ARG_ptr != 0)
    key_put ((struct key *) STAP_ARG_ptr);
%}  


/* We cache the last $keyring value for this thread.  Relying on this
   table instead of direct access to $keyring at the
   join_session_keyring function label is undesirable.  This is
   because we don't have a very good way of keeping this table clean
   (to remove old entries).  (Extraordinary measures could include
   catching thread deaths, or returns from *callers* of
   find_keyring_by_name.)  So what we do here instead is label keyrings%
   as an auto-wrapping array, so *old* entries will be reused. */
global keyrings%, warned_keyrings_p
probe kernel.function("find_keyring_by_name").return
{
  keyrings[tid()] = $return
}

/* And same for the $new variable.  :-( */
global news%, warned_news_p
probe kernel.function("prepare_creds").return
{
  news[tid()] = $return
}

/* Disable the automatic dumping of these globals. */
probe never
{
  println(keyrings[0])
  println(news[0])
  println(warned_keyrings_p+1)
  println(warned_news_p+1)
}
