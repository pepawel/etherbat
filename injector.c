#include <stdio.h>
#include <libnet.h>
#include <glib.h>

#define PNAME "injector"

typedef struct {
  u_int8_t enet_src[6];
  u_int8_t enet_dst[6];
  u_int16_t protocol;
  u_int8_t arp_smac[6];
  u_int8_t arp_sip[4];
  u_int8_t arp_tmac[6];
  u_int8_t arp_tip[4];
  u_int16_t arp_op;
} frame_t;

void
usage() {
  printf("Usage:\n");
  printf("\t%s <interface>\n", PNAME);
  return;
}

/* Convert MAC in hexadecimal string format to array of bytes.
 * Return 1 on success, 0 on failure. */
int
mac_text2byte(u_int8_t *mac, char *text) {
  u_int8_t *tmp;
  int tmp2;

  tmp = libnet_hex_aton((int8_t*)text, &tmp2);
  if (NULL == tmp) {
    return 0;
  }
  memcpy(mac, tmp, 6);
  free(tmp);
  return 1;
}

/* Convert IP in dot separated string format to array of bytes.
 * Return 1 on success, 0 on failure. */
int
ip_text2byte(u_int8_t *ip, char *text) {
  struct in_addr ip_struct;

  if (!inet_aton(text, &ip_struct)) {
    return 0;
  }
  memcpy(ip, (void*) &ip_struct, 4);
  return 1;
}

/* Get line from standard input, parse it and fill the frame with
 * extracted data.
 * Return 1 on success, 0 on failure */
int
parse_line(frame_t *f) {
  char buf[256];
  gchar **tab;
  int count, ret;
  long int tmp;

  if (NULL == fgets(buf, sizeof(buf), stdin)) {
    return 0;
  }
  /* Delete new-line character if it exists */
  if(buf[strlen(buf) - 1] == '\n') {
    buf[strlen(buf) - 1] = 0;
  }

  /* Split line */
  tab = g_strsplit(buf, " ", 12);
  count = g_strv_length(tab);

  if (0 == count) {
    fprintf(stderr, "%s: zero length line\n", PNAME);
    goto quit;
  }

  if (0 == strcmp(tab[0], "exit")) {
    goto quit;
  }

  if (count < 6) {
    fprintf(stderr, "%s: frame too short\n", PNAME);
    goto quit;
  }

  /* Fill ethernet frame header */
  ret = mac_text2byte(f->enet_src, tab[2]);
  if (!ret) {
    fprintf(stderr, "%s: invalid source mac address\n", PNAME);
    goto quit;
  }
  
  ret = mac_text2byte(f->enet_dst, tab[4]);
  if (!ret) {
    fprintf(stderr, "%s: invalid destination mac address\n", PNAME);
    goto quit;
  }

  /* Find out protocol */
  tmp = strtol(tab[5], NULL, 16);
  if (0 == strcmp(tab[5], "ARP")) {
    f->protocol = ETHERTYPE_ARP;
  } else if (0 == strcmp(tab[5], "IP")) {
    f->protocol = ETHERTYPE_IP;
  } else if (tmp >= 0 && ret < 65536) {
    f->protocol = tmp;
  } else {
    fprintf(stderr, "%s: protocol invalid\n", PNAME);
    goto quit;
  }

  /* Fill ARP header */
  if (ETHERTYPE_ARP == f->protocol) {
    if (count < 11) {
      fprintf(stderr, "%s: ARP packet too short\n", PNAME);
      goto quit;
    }

    if (0 == strcmp(tab[6], "Request")) {
      f->arp_op = ARPOP_REQUEST;
    } else if (0 == strcmp(tab[6], "Reply")) {
      f->arp_op = ARPOP_REPLY;
    } else {
      tmp = strtol(tab[5], NULL, 16);
      if (tmp < 0 || ret >= 65536) {
        fprintf(stderr, "%s: protocol invalid\n", PNAME);
        goto quit;
      }
      f->arp_op = tmp;
    }

    ret = mac_text2byte(f->arp_smac, tab[7]);
    if (!ret) {
      fprintf(stderr, "%s: invalid ARP sender mac address\n", PNAME);
      goto quit;
    }

    ret = ip_text2byte(f->arp_sip, tab[8]);
    if (!ret) {
      fprintf(stderr, "%s: invalid ARP sender ip address\n", PNAME);
      goto quit;
    }

    ret = mac_text2byte(f->arp_tmac, tab[9]);
    if (!ret) {
      fprintf(stderr, "%s: invalid ARP target mac address\n", PNAME);
      goto quit;
    }

    ret = ip_text2byte(f->arp_tip, tab[10]);
    if (!ret) {
      fprintf(stderr, "%s: invalid ARP target ip address\n", PNAME);
      goto quit;
    }
  }

  return 1;
quit:
  g_strfreev(tab);
  return 0;
}

/* Inject given frame.
 * Return 1 on success, 0 on failure. */
int
inject_frame(libnet_t *l, frame_t *f) {
  libnet_ptag_t t;

  if (ETHERTYPE_ARP == f->protocol) {
    t = libnet_autobuild_arp(
        f->arp_op,
        f->arp_smac,
        f->arp_sip,
        f->arp_tmac,
        f->arp_tip,
        l);
    if (t == -1) {
      fprintf(stderr, "%s: building of ARP header failed: %s\n",
              PNAME, libnet_geterror(l));
      return 0;
    }
  }

  t = libnet_build_ethernet(
      f->enet_dst,
      f->enet_src,
      f->protocol,
      NULL,
      0,
      l,
      0);
  if (t == -1) {
    fprintf(stderr, "%s: building of ethernet header failed: %s\n",
            PNAME, libnet_geterror(l));
    return 0;
  }
                                  
  if (-1 == libnet_write(l)) {
    fprintf(stderr, "%s: injecting frame failed: %s\n",
            PNAME, libnet_geterror(l));
    return 0;
  } else {
    libnet_clear_packet(l);
    return 1;
  }
}

int
main(int argc, char *argv[]) {
  char *device;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_t *l;
  frame_t frame;

  if (argc < 2) {
    usage();
    exit(EXIT_FAILURE);
  }
  device=argv[1];

  l = libnet_init(LIBNET_LINK, device, errbuf);
  if (l == NULL) {
    fprintf(stderr, "%s: libnet initialization failed: %s\n",
            PNAME, errbuf);
    exit(EXIT_FAILURE);
  }

  printf("OK Ready\n");
  fflush(stdout);
  while(1) {
    if (!parse_line(&frame)) break;
    if (!inject_frame(l, &frame)) break;
  }

  libnet_destroy(l);

  return 0;
}
