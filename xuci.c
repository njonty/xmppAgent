#ifdef OPENWRT
#include <uci.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xuci.h"

static struct uci_context *ctx;
static const char *delimiter = " ";



static void uci_print_value(char *output, const char *v)
{

	while (*v) {
		if (*v != '\'')
			*output = *v;
		else
			sprintf(output, "'\\''");
		v++;
		output++;
	}
}

static void uci_show_value(struct uci_option *o, char *value, bool quote)
{
	struct uci_element *e;
	bool sep = false;
	char *space;
	char *p = value;

	switch(o->type) {
	case UCI_TYPE_STRING:
		if (quote)
			uci_print_value(value, o->v.string);
		else
			strcpy(value, o->v.string);
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			p += sprintf(p, "%s", (sep ? delimiter : ""));
//			printf("%s", (sep ? delimiter : ""));
			space = strpbrk(e->name, " \t\r\n");
			if (!space && !quote)
				p += sprintf(p, "%s", e->name);
//				printf("%s", e->name);
			else
				uci_print_value(value, e->name);
			sep = true;
		}
		break;
	default:
		printf("<unknown>\n");
		break;
	}
}

int do_uci_set(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[2048];
	int ret = UCI_OK;



	ctx = uci_alloc_context();

	sprintf(cmd, "%s=%s", option, value);

	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_set(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_add_list(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;



	ctx = uci_alloc_context();

	sprintf(cmd, "%s=%s", option, value);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_add_list(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_del_list(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;



	ctx = uci_alloc_context();

	sprintf(cmd, "%s=%s", option, value);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_del_list(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_get(char *option, char *value)
{
	struct uci_element *e;
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;



	ctx = uci_alloc_context();

	sprintf(cmd, "%s", option);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	if (ptr.value){
		uci_free_context(ctx);
		return -1;
	}

	e = ptr.last;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
			ctx->err = UCI_ERR_NOTFOUND;
			uci_free_context(ctx);
			return -1;
	}
	switch(e->type) {
	case UCI_TYPE_SECTION:
		strcpy(value, ptr.s->type);
		break;
	case UCI_TYPE_OPTION:
		uci_show_value(ptr.o, value,false);
		break;
	default:
		break;
	}

	uci_free_context(ctx);
	return ret;

}

int do_uci_commit(char *package)
{
	struct uci_ptr ptr;
	int ret = -1;


	ctx = uci_alloc_context();

	if (uci_lookup_ptr(ctx, &ptr, package, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	ret = uci_commit(ctx, &ptr.p, false);
	if(ret != UCI_OK) {
		goto out;
	}

out:
	if (ptr.p)
		uci_unload(ctx, ptr.p);
	uci_free_context(ctx);
	return ret;

}

int do_uci_add(char *option, char *section, char *name)
{
	struct uci_package *p = NULL;
	struct uci_section *s = NULL;
	int ret;


	ctx = uci_alloc_context();

	if(option == NULL || section == NULL){
		uci_free_context(ctx);
		return -1;
	}

	ret = uci_load(ctx, option, &p);
	if (ret != UCI_OK)
		goto done;

	ret = uci_add_section(ctx, p, section, &s);
	if (ret != UCI_OK)
		goto done;

	ret = uci_save(ctx, p);

done:
	if (ret != UCI_OK){
		uci_free_context(ctx);
		return -1;
	}
	else if (s && name != NULL) {
		strcpy(name, s->e.name);

		uci_free_context(ctx);
	}

	return ret;
}

int do_uci_delete(char *option, char *value)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK, dummy;



	ctx = uci_alloc_context();



	if(value != NULL)
		sprintf(cmd, "%s=%s", option, value);
	else
		sprintf(cmd, "%s", option);
	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	if (ptr.value && !sscanf(ptr.value, "%d", &dummy)){
		uci_free_context(ctx);
		return -1;
	}
	ret = uci_delete(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;
}

int do_uci_rename(char *option, char *name)
{
	struct uci_ptr ptr;
	char cmd[256];
	int ret = UCI_OK;



	ctx = uci_alloc_context();

	sprintf(cmd, "%s=%s", option, name);

	if (uci_lookup_ptr(ctx, &ptr, cmd, true) != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

//	if (!ptr.value)
//		return -1;

	ret = uci_rename(ctx, &ptr);

	if (ret == UCI_OK)
		ret = uci_save(ctx, ptr.p);

	if (ret != UCI_OK) {
		uci_free_context(ctx);
		return -1;
	}

	uci_free_context(ctx);
	return ret;

}
#endif
