}

int
main (void)
{
	GObject *out;

	out = transfer_full_func (g_object_new (G_TYPE_OBJECT, NULL));
	g_object_unref (out);

	return 0;
}
