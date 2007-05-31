#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>

#define PNAME "sniffer"
#define max(a,b) ((a)>(b) ? (a) : (b))

/* To sniff or not to sniff... */
int global_do_sniff = 0;

void
usage() {
  printf("Usage:\n");
  printf("\t%s <interface>\n", PNAME);
  return;
}

char *
mac_byte2text(u_char *b, char *text) {
  sprintf(text, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
          b[0],b[1],b[2],b[3],b[4],b[5]);
  return text;
}

char *
ip_byte2text(u_char *b, char *text) {
  sprintf(text, "%d.%d.%d.%d", b[0],b[1],b[2],b[3]);
  return text;
}

/* Get frame from specified pcap handle, decode frame and print it
 * along with direction specified in dir.
 * Return 1 on success, 0 on failure. */
int
print_frame(pcap_t *p, char dir) {
  struct pcap_pkthdr *h;
  u_char *d;
  int ret;
  /* Place to store frame and protocol data text */
  char ft[256], pt[256];
  /* Frame data */
  char enet_src_text[24];
  char enet_dst_text[24];
  u_int16_t protocol;
  char protocol_text[16];
  /* ARP data */
  u_int16_t arp_op;
  char arp_op_text[16];
  char arp_smac_text[24];
  char arp_sip_text[24];
  char arp_tmac_text[24];
  char arp_tip_text[24];

  /* We don't know if there is any packet to fetch and print.
   * select + bpf + pcap_direction on the same interface goes crazy:
   * when there is frame in one direction, select() set both (in & out)
   * descriptors.
   * The only way to see if there is really a frame on pcap_t
   * is to try to fetch data from it. */
  ret = pcap_next_ex(p, &h, (const u_char**)&d);
  if (1 == ret) {
    /* If global_do_sniff not set don't process the frame. */
    if (!global_do_sniff) {
      return 1;
    }
    if(h->caplen < 14) {
      fprintf(stderr, "%s: Frame too short: %d\n", PNAME, ret);
      return 0;
    }
    /* Network order -> host order */
    protocol=(*(d+12))*256 + (*(d+13));

    if (protocol == 0x0806) {
      if(h->caplen < 42) {
        fprintf(stderr, "%s: ARP packet too short: %d\n", PNAME, ret);
        return 0;
      }
      strcpy(protocol_text, "ARP"); /* Used later in frame text building */

      /* Network order -> host order */
      arp_op = (*(d+20))*256 + (*(d+21));
      if (arp_op == 0x0001) {
        strcpy(arp_op_text, "Request");
      } else if (arp_op == 0x0002) {
        strcpy(arp_op_text, "Reply");
      } else {
        sprintf(arp_op_text, "%.4x", arp_op);
      }

      sprintf(pt, " %s %s %s %s %s",
              arp_op_text,
              mac_byte2text(d+22, arp_smac_text),
              ip_byte2text(d+28, arp_sip_text),
              mac_byte2text(d+32, arp_tmac_text),
              ip_byte2text(d+38, arp_tip_text));
    } else {
      if (protocol == 0x0800) {
        strcpy(protocol_text, "IP");
      } else {
        sprintf(protocol_text, "%.4x", protocol);
      }
      /* Don't print protocol data */
      pt[0] = 0;
    }

    /* Repetition of first character required for
     * ruby-timeout-readline-too-short bug work-around */
    sprintf(ft, "%c%c %ld.%.6ld %s > %s %s",
            dir, dir, h->ts.tv_sec, h->ts.tv_usec,
            mac_byte2text(d+6, enet_src_text),
            mac_byte2text(d, enet_dst_text),
            protocol_text);

    /* Finally print frame and protocol data text */
    printf("%s%s\n", ft, pt);
    fflush(stdout);
    return 1;
  } else if (0 == ret) {
    /* select() lied about frame readiness. Ignore. */
    return 1;
  } else {
    /* Pcap error */
    return 0;
  }
}

int
run_command(FILE* s) {
  char buf[256];

  if (NULL == fgets(buf, sizeof(buf), s)) {
    return 0;
  }

  if (0 == strncmp(buf, "start", 5)) {
    global_do_sniff = 1;
    /* Only start needs to be acknowledged */
    printf("OK Sniffing started\n");
    fflush(stdout);
    return 1;
  } else if (0 == strncmp(buf, "stop", 4)) {
    global_do_sniff = 0;
    printf("OK Sniffing stopped\n");
    fflush(stdout);
    return 1;
  } else if (0 == strncmp(buf, "exit", 4)) {
    return 0;
  } else {
    fprintf(stderr, "%s: invalid command: %s\n", PNAME, buf);
    return -1;
  }
}

int
main(int argc, char *argv[]) {
  char *device;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *in, *out;
  int in_fd, out_fd, stdin_fd, max_fd;
  int ret;
  fd_set fds;

  if (argc < 2) {
    usage();
    exit(1);
  }
  device=argv[1];

  /* Open devices */
  in = pcap_open_live (device, 64, 1, 0, errbuf);
  if (in == NULL) {
    fprintf(stderr, "%s: pcap_open_live() (in): %s\n",
    PNAME, errbuf);
    exit(1);
  }
  out = pcap_open_live (device, 64, 1, 0, errbuf);
  if (out == NULL) {
    fprintf(stderr, "%s: pcap_open_live() (out): %s\n",
    PNAME, errbuf);
    exit(1);
  }

  /* Set directions */
  if (-1 == pcap_setdirection (in, PCAP_D_IN)) {
    fprintf(stderr, "%s: pcap_setdirection error() (in)\n",
    PNAME);
    exit(1);
  }
  if (-1 == pcap_setdirection (out, PCAP_D_OUT)) {
    fprintf(stderr, "%s: pcap_setdirection error() (out)\n",
    PNAME);
    exit(1);
  }

  /* Get descriptors */
  in_fd = pcap_get_selectable_fd(in);
  if (-1 == in_fd) {
    fprintf(stderr, "%s: pcap_get_selectable_fd() (in): %s\n",
    PNAME, errbuf);
    exit(1);
  }
  out_fd = pcap_get_selectable_fd(out);
  if (-1 == out_fd) {
    fprintf(stderr, "%s: pcap_get_selectable_fd() (out): %s\n",
    PNAME, errbuf);
    exit(1);
  }

  stdin_fd = fileno(stdin);
  if (-1 == stdin_fd) {
    fprintf(stderr, "%s: fdopen(): %s\n", PNAME, strerror(errno));
    exit(1);
  }
  max_fd = max(stdin_fd, max(in_fd, out_fd)) + 1;

  printf("OK Ready\n");
  fflush(stdout);

  while (1) {
    FD_ZERO(&fds);
    FD_SET(in_fd, &fds);
    FD_SET(out_fd, &fds);
    FD_SET(stdin_fd, &fds);

    ret = select(max_fd, &fds, NULL, NULL, NULL);
    if (ret < 0) {
      fprintf(stderr, "%s: select(): %s\n", PNAME, strerror(errno));
      exit(1);
    } else if (0 == ret) {
      fprintf(stderr, "%s: select() returned zero\n", PNAME);
      exit(1);
    }

    if (FD_ISSET(in_fd, &fds)) {
      if (!print_frame(in, 'i')) {
        fprintf(stderr, "%s: error processing frame (in)\n", PNAME);
        break;
      }
    }
    if (FD_ISSET(out_fd, &fds)) {
      if (!print_frame(out, 'o')) {
        fprintf(stderr, "%s: error processing frame (out)\n", PNAME);
        break;
      }
    }
    if (FD_ISSET(stdin_fd, &fds)) {
      ret = run_command(stdin);
      if (-1 == ret) {
        fprintf(stderr, "%s: error processing command\n", PNAME);
        break;
      } else if (0 == ret) {
        /* Exit requested -- silently quit */
        break;
      }
    }
  }

  /* Clean up */
  pcap_close(in);
  pcap_close(out);

  return 0;
}
