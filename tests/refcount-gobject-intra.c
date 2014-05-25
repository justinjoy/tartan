/* Template: refcount-intra */

/*
 * No error
 */
{
	/* Pass the reference straight through. */
	return in;
}

/*
 * TODO
 */
{
	/* Add and leak an extra reference. */
	return g_object_ref (in);
}

/*
 * TODO
 */
{
	/* Add and leak an extra reference a different way. */
	g_object_ref (in);
	return in;
}

/*
 * TODO
 */
{
	/* Steal a reference and cause a double-unref. */
	g_object_unref (in);
	return in;
}

/*
 * No error
 */
{
	/* Steal a reference but then don't transfer the object out. */
	g_object_unref (in);
	return NULL;
}

/*
 * No error
 */
{
	/* Return a different object. */
	g_object_unref (in);
	return g_object_new (G_TYPE_OBJECT, NULL);
}

/*
 * No error
 */
{
	GObject *out;

	/* Return a different object via a temporary. */
	g_object_unref (in);
	out = g_object_new (G_TYPE_OBJECT, NULL);
	return out;
}
