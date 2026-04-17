#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/fl_ask.H>
#include <FL/Fl_Native_File_Chooser.H>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

// ── Constants ─────────────────────────────────────────────────────────────────

#define BUF_SIZE     64
#define SPD_BIN      "/tmp/spdtmp/spd_dump"
#define SPD_REPO     "https://github.com/TomKing062/spreadtrum_flash"
#define EXEC_REPO_V1 "https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/raw/refs/heads/info/soc"
#define EXEC_REPO_V2 "https://github.com/TomKing062/exec_addr_v2/raw/refs/heads/main/soc"
#define SPD_TMPBLD   "/tmp/spd_build"
#define SPD_TMPDIR   "/tmp/spdtmp"

// ── Layout constants ──────────────────────────────────────────────────────────

static const int WIN_W    = 860;
static const int WIN_H    = 620;
static const int LEFT_X   = 10;
static const int LEFT_W   = 260;
static const int LABEL_W  = 50;
static const int PICK_W   = 28;
static const int PICK_GAP = 4;
static const int INPUT_X  = LEFT_X + LABEL_W;
static const int INPUT_W  = LEFT_W - LABEL_W - PICK_GAP - PICK_W;
static const int PICK_X   = INPUT_X + INPUT_W + PICK_GAP;
static const int LOG_X    = LEFT_W + 20;
static const int LOG_W    = WIN_W - LOG_X - 10;
static const int LOG_H    = WIN_H - 20;
static const int ROW_H    = 30;
static const int OPT_H    = 26;
static const int GAP      = 8;

// 2-column button grid
static const int BCOL_GAP = 4;
static const int BCOL_W   = (LEFT_W - BCOL_GAP) / 2;   // ~128px each
static const int BCOL0_X  = LEFT_X;
static const int BCOL1_X  = LEFT_X + BCOL_W + BCOL_GAP;
static const int BTN_H    = 28;
static const int BTN_GAP  = 4;

// Number of action buttons (left col + right col)
#define N_ACTION_BTNS 11

// ── Widget globals ─────────────────────────────────────────────────────────────

static Fl_Button        *btn_exec;
static Fl_Choice        *cpu_choice;
static Fl_Input         *fdl1_input;
static Fl_Input         *fdl2_input;
static Fl_Input         *exec_input;
static Fl_Input         *fexec_input;
static Fl_Input         *save_input;
static Fl_Text_Display  *output;
static Fl_Text_Buffer   *log_buf;

// ── Option widgets ────────────────────────────────────────────────────────────

static Fl_Check_Button  *chk_verbose;
static Fl_Choice        *verbose_choice;
static Fl_Check_Button  *chk_kick;
static Fl_Check_Button  *chk_kickto;
static Fl_Input         *kickto_input;

// slot selector — used by set_active and write_parts
static Fl_Choice        *slot_choice;   // "auto / a / b"

// reset after op
static Fl_Check_Button  *chk_reset_after;

// ── Action buttons ────────────────────────────────────────────────────────────

static Fl_Button *action_btns[N_ACTION_BTNS];

// ── Resolved address / file state ─────────────────────────────────────────────

static char g_fdl1[BUF_SIZE];
static char g_fdl2[BUF_SIZE];
static char g_exec[BUF_SIZE];
static char selected_files[64][256];
static int  selected_count = 0;

// ── Thread state ──────────────────────────────────────────────────────────────

static bool g_busy = false;

// ── Colors ────────────────────────────────────────────────────────────────────

static const Fl_Color COL_BG       = fl_rgb_color(28,  28,  28);
static const Fl_Color COL_FG       = fl_rgb_color(210, 210, 210);
static const Fl_Color COL_WIDGET   = fl_rgb_color(40,  40,  40);
static const Fl_Color COL_INPUT_BG = fl_rgb_color(22,  22,  22);
static const Fl_Color COL_INPUT_FG = fl_rgb_color(100, 200, 160);
static const Fl_Color COL_LOG_BG   = fl_rgb_color(12,  12,  12);
static const Fl_Color COL_LOG_FG   = fl_rgb_color(80,  200, 100);
static const Fl_Color COL_GREEN    = fl_rgb_color(100, 200, 120);
static const Fl_Color COL_AMBER    = fl_rgb_color(210, 140, 30);
static const Fl_Color COL_RED      = fl_rgb_color(180, 60,  50);
static const Fl_Color COL_MUTED    = fl_rgb_color(130, 130, 130);
static const Fl_Color COL_BLUE     = fl_rgb_color(80,  150, 220);

// ── Thread-safe logging ───────────────────────────────────────────────────────

static void log_append(const char *text) {
    Fl::lock();
    log_buf->append(text);
    output->scroll(log_buf->length(), 0);
    Fl::unlock();
    Fl::awake();
}

static void log_line(const char *text) { log_append(text); log_append("\n"); }

// ── Enable / disable action buttons ──────────────────────────────────────────

static void set_buttons_enabled(bool on) {
    Fl::lock();
    for (int i = 0; i < N_ACTION_BTNS; i++) {
        if (on) action_btns[i]->activate();
        else    action_btns[i]->deactivate();
    }
    Fl::unlock();
    Fl::awake();
}

// ── Run command ───────────────────────────────────────────────────────────────

static int run_command(const char *cmd, bool silent = false) {
    char wrapped[4096];
    snprintf(wrapped, sizeof(wrapped), "%s 2>&1", cmd);
    if (!silent) { log_append("[>] "); log_append(cmd); log_append("\n"); }
    FILE *fp = popen(wrapped, "r");
    if (!fp) { if (!silent) log_line("[-] popen failed"); return -1; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) { if (!silent) log_append(line); }
    return pclose(fp);
}

// ── File size ─────────────────────────────────────────────────────────────────

static long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

// ── Resolve addresses ─────────────────────────────────────────────────────────

static bool resolve_addresses() {
    const char *cpu = cpu_choice->text(cpu_choice->value());
    if (!cpu || cpu[0] == '\0') { log_line("[-] No CPU selected"); return false; }

    if (!strcmp(cpu,"sc9863a")||!strcmp(cpu,"sc9832e")||!strcmp(cpu,"sc9820e")) {
        strcpy(g_fdl1,"0x5000"); strcpy(g_fdl2,"0x9efffe00"); strcpy(g_exec,"0x4ee8");
    } else if (!strcmp(cpu,"ud710")||!strcmp(cpu,"ums312")||!strcmp(cpu,"ums512")) {
        strcpy(g_fdl1,"0x5500"); strcpy(g_fdl2,"0x9efffe00"); strcpy(g_exec,"0x3f28");
    } else if (!strcmp(cpu,"udx710")) {
        strcpy(g_fdl1,"0x28007000"); strcpy(g_fdl2,"0x9efffe00"); strcpy(g_exec,"0x3f28");
    } else if (!strcmp(cpu,"ums9230")) {
        strcpy(g_fdl1,"0x65000800"); strcpy(g_fdl2,"0x9efffe00"); strcpy(g_exec,"0x65015f08");
    } else if (!strcmp(cpu,"ums9620")) {
        strcpy(g_fdl1,"0x65000800"); strcpy(g_fdl2,"0xb4fffe00"); strcpy(g_exec,"0x65012f48");
    } else if (!strcmp(cpu,"ums9621")) {
        strcpy(g_fdl1,"0x65000800"); strcpy(g_fdl2,"0xbefffe00"); strcpy(g_exec,"0x65017f08");
    } else if (!strcmp(cpu,"Custom")) {
        const char *v1=fdl1_input->value(), *v2=fdl2_input->value(), *ve=exec_input->value();
        if (!v1||!v1[0]||!v2||!v2[0]||!ve||!ve[0]) {
            log_line("[-] Custom CPU: fill in all three address fields"); return false;
        }
        strncpy(g_fdl1,v1,BUF_SIZE-1); strncpy(g_fdl2,v2,BUF_SIZE-1); strncpy(g_exec,ve,BUF_SIZE-1);
        g_fdl1[BUF_SIZE-1]=g_fdl2[BUF_SIZE-1]=g_exec[BUF_SIZE-1]='\0';
    } else { log_line("[-] Unknown CPU"); return false; }

    char msg[256];
    snprintf(msg,sizeof(msg),"[*] fdl1=%s  fdl2=%s  exec=%s\n",g_fdl1,g_fdl2,g_exec);
    log_append(msg);
    return true;
}

// ── Validate fdl files ────────────────────────────────────────────────────────

static bool validate_fdls() {
    const char *f1 = fdl1_input->value();
    const char *f2 = fdl2_input->value();
    if (!f1||!f1[0]) { fl_alert("fdl1 is not selected!"); log_line("[-] fdl1 missing"); return false; }
    if (!f2||!f2[0]) { fl_alert("fdl2 is not selected!"); log_line("[-] fdl2 missing"); return false; }
    if (access(f1,F_OK)!=0) { fl_alert("fdl1 file not found!"); log_line("[-] fdl1 not found"); return false; }
    if (access(f2,F_OK)!=0) { fl_alert("fdl2 file not found!"); log_line("[-] fdl2 not found"); return false; }
    return true;
}

// ── exec binary helpers ───────────────────────────────────────────────────────

static const char *get_exec_repo(const char *cpu) {
    return (cpu && !strcmp(cpu,"ums9621")) ? EXEC_REPO_V2 : EXEC_REPO_V1;
}

static void build_exec_bin_name(char *out, size_t sz, const char *addr) {
    const char *hex = addr;
    if (!strncmp(hex,"0x",2)) hex += 2;
    snprintf(out, sz, "custom_exec_no_verify_%s.bin", hex);
}

static bool ensure_exec_bin(const char *cpu) {
    const char *manual = fexec_input->value();
    if (manual && manual[0] && access(manual, F_OK) == 0) {
        log_append("[+] using manually selected exec bin\n");
        return true;
    }
    const char *repo = get_exec_repo(cpu);
    char exec_bin[128], full_path[256];
    build_exec_bin_name(exec_bin, sizeof(exec_bin), g_exec);
    snprintf(full_path, sizeof(full_path), SPD_TMPDIR "/%s", exec_bin);
    if (access(full_path, F_OK) == 0) { log_append("[+] exec bin already present\n"); return true; }
    char url[512], cmd[1024];
    snprintf(url, sizeof(url), "%s/%s/%s", repo, cpu ? cpu : "unknown", exec_bin);
    snprintf(cmd, sizeof(cmd), "curl -L \"%s\" -o \"%s\"", url, full_path);
    log_append("[*] fetching exec payload: "); log_append(url); log_append("\n");
    if (run_command(cmd, true) != 0) { log_append("[-] exec download failed — place manually\n"); return false; }
    log_append("[+] exec bin ready\n");
    return true;
}

// ── Build prefix ──────────────────────────────────────────────────────────────

static void build_prefix(char *buf, size_t len,
                          const char *fdl1_path, const char *fdl2_path,
                          const char *exec_bin_path, const char *extra_flags) {
    snprintf(buf, len,
        SPD_BIN " %s--wait 300 exec_addr %s "
        "fdl \"%s\" %s fdl \"%s\" %s exec",
        extra_flags, g_exec,
        fdl1_path, g_fdl1,
        fdl2_path, g_fdl2);
    if (exec_bin_path && exec_bin_path[0]) {
        strncat(buf, " \"", len - strlen(buf) - 1);
        strncat(buf, exec_bin_path, len - strlen(buf) - 1);
        strncat(buf, "\"", len - strlen(buf) - 1);
    }
}

// ── Build extra flags ─────────────────────────────────────────────────────────

static void build_extra_flags(char *out, size_t sz,
                               bool verbose_en, int verbose_level,
                               bool kick_en, bool kickto_en, int kickto_val) {
    out[0] = '\0';
    if (verbose_en) {
        char tmp[32]; snprintf(tmp, sizeof(tmp), "--verbose %d ", verbose_level);
        strncat(out, tmp, sz - strlen(out) - 1);
    }
    if (kick_en) {
        strncat(out, "--kick ", sz - strlen(out) - 1);
    } else if (kickto_en) {
        if (kickto_val < 0) kickto_val = 0;
        if (kickto_val > 127) kickto_val = 127;
        char tmp[32]; snprintf(tmp, sizeof(tmp), "--kickto %d ", kickto_val);
        strncat(out, tmp, sz - strlen(out) - 1);
    }
}

// ── spd_dump build thread ─────────────────────────────────────────────────────

static void *build_spd_thread(void *) {
    if (access(SPD_BIN, X_OK) == 0) { log_line("[+] spd_dump already ready"); return nullptr; }
    log_line("[*] Building spd_dump from source...");
    system("rm -rf " SPD_TMPBLD);
    system("mkdir -p " SPD_TMPDIR);
    if (run_command("git clone " SPD_REPO " " SPD_TMPBLD, true) != 0) { log_line("[-] git clone failed"); return nullptr; }
    if (run_command("make -C " SPD_TMPBLD, true) != 0) { log_line("[-] make failed"); return nullptr; }
    if (run_command("mv " SPD_TMPBLD "/spd_dump " SPD_BIN " && chmod +x " SPD_BIN, true) != 0) { log_line("[-] install failed"); return nullptr; }
    system("rm -rf " SPD_TMPBLD);
    log_line("[+] spd_dump ready at " SPD_BIN);
    return nullptr;
}

static void setup_spd_dump_cb(void *) {
    pthread_t t;
    pthread_create(&t, nullptr, build_spd_thread, nullptr);
    pthread_detach(t);
}

// ── Thread argument struct ────────────────────────────────────────────────────

struct OpArgs {
    int  op;
    char cpu[64];
    char fdl1[512];
    char fdl2[512];
    char fexec[512];
    char save[512];
    char param[512];     // partition name / image path / slot ("a"/"b") / write_parts dir
    char files[64][256];
    int  file_count;
    // option flags
    bool verbose_en;
    int  verbose_level;
    bool kick_en;
    bool kickto_en;
    int  kickto_val;
    // slot override for write_parts: 0=auto, 1=a, 2=b
    int  slot;
    bool reset_after;   // append "reset" to command after the main op
};

// ── Worker thread ─────────────────────────────────────────────────────────────

static void filename_to_part(const char *path, char *out, size_t out_sz) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    strncpy(out, name, out_sz - 1);
    out[out_sz - 1] = '\0';
    char *dot = strrchr(out, '.');
    if (dot && (!strcmp(dot,".img")||!strcmp(dot,".bin"))) *dot = '\0';
}

static void *op_thread(void *arg) {
    OpArgs *a = (OpArgs *)arg;

    ensure_exec_bin(a->cpu);

    char exec_bin_path[512] = "";
    if (a->fexec[0] && access(a->fexec, F_OK) == 0) {
        strncpy(exec_bin_path, a->fexec, sizeof(exec_bin_path)-1);
    } else {
        char exec_bin[128];
        build_exec_bin_name(exec_bin, sizeof(exec_bin), g_exec);
        snprintf(exec_bin_path, sizeof(exec_bin_path), SPD_TMPDIR "/%s", exec_bin);
        if (access(exec_bin_path, F_OK) != 0) exec_bin_path[0] = '\0';
    }

    char extra_flags[128];
    build_extra_flags(extra_flags, sizeof(extra_flags),
                      a->verbose_en, a->verbose_level,
                      a->kick_en, a->kickto_en, a->kickto_val);
    if (extra_flags[0]) { log_append("[*] flags: "); log_append(extra_flags); log_append("\n"); }

    char prefix[1024];
    build_prefix(prefix, sizeof(prefix), a->fdl1, a->fdl2, exec_bin_path, extra_flags);

    char cmd[8192];

    switch (a->op) {

    // ── op 1: dump all ────────────────────────────────────────────────────────
    case 1:
        snprintf(cmd, sizeof(cmd), "cd \"%s\" && %s r all", a->save, prefix);
        log_line("[*] Dumping full eMMC...");
        run_command(cmd);
        log_line("[+] Done.");
        break;

    // ── op 2: dump partitions ─────────────────────────────────────────────────
    case 2: {
        snprintf(cmd, sizeof(cmd), "cd \"%s\" && %s ", a->save, prefix);
        char parts[32][64]; int n = 0;
        const char *p = a->param;
        while (*p && n < 32) {
            while (*p == ' ' || *p == ',') p++;
            if (!*p) break;
            const char *e = p; while (*e && *e != ',') e++;
            int len = (int)(e - p);
            if (len > 0 && len < 64) { strncpy(parts[n], p, len); parts[n][len] = '\0'; n++; }
            p = e;
        }
        for (int i = 0; i < n; i++) {
            char chunk[256];
            snprintf(chunk, sizeof(chunk), "read_part %s 0 0 %s.img ", parts[i], parts[i]);
            strncat(cmd, chunk, sizeof(cmd) - strlen(cmd) - 1);
        }
        log_line("[*] Dumping partitions...");
        run_command(cmd);
        log_line("[+] Done.");
        break;
    }

    // ── op 3: flash selected partition images ─────────────────────────────────
    case 3: {
        snprintf(cmd, sizeof(cmd), "%s ", prefix);
        for (int i = 0; i < a->file_count; i++) {
            const char *file = a->files[i];
            long sz = get_file_size(file);
            if (sz < 0) { log_append("[-] cannot stat: "); log_append(file); log_append("\n"); continue; }
            char part[128]; filename_to_part(file, part, sizeof(part));
            char chunk[512];
            snprintf(chunk, sizeof(chunk), "write_part %s 0 %ld \"%s\" ", part, sz, file);
            strncat(cmd, chunk, sizeof(cmd) - strlen(cmd) - 1);
        }
        log_line("[*] Flashing partitions...");
        run_command(cmd);
        log_line("[+] Done.");
        break;
    }

    // ── op 4: flash full image ────────────────────────────────────────────────
    case 4: {
        long sz = get_file_size(a->param);
        if (sz < 0) { char err[1024]; snprintf(err,sizeof(err),"[-] Cannot stat '%s'\n",a->param); log_append(err); break; }
        snprintf(cmd, sizeof(cmd), "%s w all \"%s\"", prefix, a->param);
        char msg[1024]; snprintf(msg,sizeof(msg),"[*] Flashing full eMMC: %s (%ld bytes)\n",a->param,sz);
        log_append(msg);
        run_command(cmd);
        log_line("[+] Done.");
        break;
    }

    // ── op 5: dump all lite ───────────────────────────────────────────────────
    case 5:
        snprintf(cmd, sizeof(cmd), "cd \"%s\" && %s r all_lite", a->save, prefix);
        log_line("[*] Dumping full eMMC (lite — skips inactive slot, blackbox, cache, userdata)...");
        run_command(cmd);
        log_line("[+] Done.");
        break;

    // ── op 6: erase partition ─────────────────────────────────────────────────
    case 6:
        snprintf(cmd, sizeof(cmd), "%s erase_part %s", prefix, a->param);
        { char msg[1024]; snprintf(msg,sizeof(msg),"[*] Erasing partition: %s\n",a->param); log_append(msg); }
        run_command(cmd);
        log_line("[+] Done.");
        break;

    // ── op 7: erase all ───────────────────────────────────────────────────────
    case 7:
        snprintf(cmd, sizeof(cmd), "%s erase_all", prefix);
        log_line("[!] Erasing ALL partitions...");
        run_command(cmd);
        log_line("[+] Done.");
        break;

    // ── op 8: set active slot ─────────────────────────────────────────────────
    case 8:
        // a->param holds "a" or "b"
        snprintf(cmd, sizeof(cmd), "%s set_active %s", prefix, a->param);
        { char msg[1024]; snprintf(msg,sizeof(msg),"[*] Setting active slot: %s\n",a->param); log_append(msg); }
        run_command(cmd);
        log_line("[+] Done.");
        break;

    // ── op 9: write_parts (restore dump) ─────────────────────────────────────
    case 9: {
        // a->param = source directory, a->slot: 0=auto, 1=force a, 2=force b
        const char *subcmd = "write_parts";
        if      (a->slot == 1) subcmd = "write_parts_a";
        else if (a->slot == 2) subcmd = "write_parts_b";
        snprintf(cmd, sizeof(cmd), "%s %s \"%s\"", prefix, subcmd, a->param);
        char msg[1024]; snprintf(msg,sizeof(msg),"[*] Writing parts from: %s  (cmd: %s)\n",a->param,subcmd);
        log_append(msg);
        run_command(cmd);
        log_line("[+] Done.");
        break;
    }

    // ── op 10: reset (standalone) ─────────────────────────────────────────────
    case 10:
        snprintf(cmd, sizeof(cmd), "%s reset", prefix);
        log_line("[*] Sending reset...");
        run_command(cmd);
        log_line("[+] Done.");
        break;

    default:
        log_line("[-] unknown op");
        break;
    }

    // ── append reset if requested (skipped for standalone reset op) ───────────
    if (a->reset_after && a->op != 10) {
        char reset_cmd[1048];
        snprintf(reset_cmd, sizeof(reset_cmd), "%s reset", prefix);
        log_line("[*] Sending reset...");
        run_command(reset_cmd);
    }

    set_buttons_enabled(true);
    g_busy = false;
    delete a;
    return nullptr;
}

// ── Spawn helper ──────────────────────────────────────────────────────────────

static void spawn_op(int op, const char *param = "") {
    if (g_busy) { fl_alert("An operation is already running."); return; }
    if (!resolve_addresses() || !validate_fdls()) return;

    if (chk_kickto->value()) {
        const char *kv = kickto_input->value();
        if (!kv || !kv[0]) { fl_alert("kickto value is empty (0-127)."); return; }
        int v = atoi(kv);
        if (v < 0 || v > 127) { fl_alert("kickto value must be 0-127."); return; }
    }

    OpArgs *a = new OpArgs();
    a->op = op;

    const char *cpu = cpu_choice->text(cpu_choice->value());
    strncpy(a->cpu,   cpu ? cpu : "",       sizeof(a->cpu)-1);
    strncpy(a->fdl1,  fdl1_input->value(),  sizeof(a->fdl1)-1);
    strncpy(a->fdl2,  fdl2_input->value(),  sizeof(a->fdl2)-1);
    strncpy(a->fexec, fexec_input->value(), sizeof(a->fexec)-1);

    const char *sv = save_input->value();
    strncpy(a->save,  (sv && sv[0]) ? sv : ".", sizeof(a->save)-1);
    strncpy(a->param, param ? param : "",        sizeof(a->param)-1);

    a->file_count = selected_count;
    for (int i = 0; i < selected_count; i++)
        strncpy(a->files[i], selected_files[i], 255);

    a->verbose_en    = chk_verbose->value() != 0;
    a->verbose_level = verbose_choice->value();
    a->kick_en       = chk_kick->value() != 0;
    a->kickto_en     = chk_kickto->value() != 0;
    a->kickto_val    = a->kickto_en ? atoi(kickto_input->value()) : 0;
    a->slot          = slot_choice->value();   // 0=auto,1=a,2=b
    a->reset_after   = chk_reset_after->value() != 0;

    g_busy = true;
    set_buttons_enabled(false);

    pthread_t t;
    pthread_create(&t, nullptr, op_thread, a);
    pthread_detach(t);
}

// ── Button callbacks ──────────────────────────────────────────────────────────

static void dump_all_cb(Fl_Widget *, void *)      { spawn_op(1); }
static void dump_all_lite_cb(Fl_Widget *, void *) { spawn_op(5); }
static void reset_cb(Fl_Widget *, void *)         { spawn_op(10); }

static void dump_part_cb(Fl_Widget *, void *) {
    const char *input = fl_input("Partitions (comma separated):", "");
    if (!input || !input[0]) return;
    spawn_op(2, input);
}

static void flash_part_cb(Fl_Widget *, void *) {
    selected_count = 0;
    while (1) {
        Fl_Native_File_Chooser fc;
        fc.title("Select partition images");
        fc.type(Fl_Native_File_Chooser::BROWSE_MULTI_FILE);
        fc.filter("Images\t*.img\nBinary\t*.bin\nAll\t*");
        if (fc.show() != 0) break;
        for (int i = 0; i < fc.count(); i++) {
            if (selected_count >= 64) { log_line("[-] Too many files"); break; }
            strncpy(selected_files[selected_count], fc.filename(i), 255);
            selected_files[selected_count][255] = '\0';
            log_append("[+] added: "); log_append(selected_files[selected_count]); log_append("\n");
            selected_count++;
        }
        if (fl_choice("Add more files?", "No (Flash now)", "Yes", nullptr) != 1) break;
    }
    if (selected_count == 0) return;
    char confirm[128];
    snprintf(confirm, sizeof(confirm), "Flash %d partition(s)?", selected_count);
    if (fl_choice("%s", "Cancel", "Flash", nullptr, confirm) != 1) { selected_count = 0; return; }
    spawn_op(3);
    selected_count = 0;
}

static void flash_all_cb(Fl_Widget *, void *) {
    const char *img = fl_input("Full flash image file:", "full.img");
    if (!img || !img[0]) return;
    spawn_op(4, img);
}

static void erase_part_cb(Fl_Widget *, void *) {
    const char *part = fl_input("Partition name to erase:", "");
    if (!part || !part[0]) return;
    char confirm[256];
    snprintf(confirm, sizeof(confirm), "Erase partition '%s'?", part);
    if (fl_choice("%s", "Cancel", "Erase", nullptr, confirm) != 1) return;
    spawn_op(6, part);
}

static void erase_all_cb(Fl_Widget *, void *) {
    // double confirmation for destructive op
    if (fl_choice("This will erase ALL partitions.\nThis cannot be undone.",
                  "Cancel", "I understand, continue", nullptr) != 1) return;
    if (fl_choice("Are you absolutely sure?", "Cancel", "Erase everything", nullptr) != 1) return;
    spawn_op(7);
}

static void set_active_cb(Fl_Widget *, void *) {
    // slot_choice: 0=auto(invalid for set_active), 1=a, 2=b
    int sv = slot_choice->value();
    if (sv == 0) {
        fl_alert("Set the slot selector to 'a' or 'b' first.");
        return;
    }
    const char *slot_str = (sv == 1) ? "a" : "b";
    char confirm[64];
    snprintf(confirm, sizeof(confirm), "Set active slot to '%s'?", slot_str);
    if (fl_choice("%s", "Cancel", "Set", nullptr, confirm) != 1) return;
    spawn_op(8, slot_str);
}

static void write_parts_cb(Fl_Widget *, void *) {
    // pick source directory
    Fl_Native_File_Chooser fc;
    fc.title("Select dump directory (source)");
    fc.type(Fl_Native_File_Chooser::BROWSE_DIRECTORY);
    if (fc.show() != 0 || !fc.filename()) return;

    const char *slot_labels[] = { "auto", "force slot a", "force slot b" };
    int sv = slot_choice->value();
    char confirm[512];
    snprintf(confirm, sizeof(confirm),
             "Write parts from:\n%s\n\nSlot: %s", fc.filename(), slot_labels[sv]);
    if (fl_choice("%s", "Cancel", "Write", nullptr, confirm) != 1) return;

    spawn_op(9, fc.filename());
}

static void clear_cb(Fl_Widget *, void *) { log_buf->text(""); }

// ── Picker callbacks ──────────────────────────────────────────────────────────

static void pick_fdl1_cb(Fl_Widget *, void *) {
    Fl_Native_File_Chooser fc; fc.title("Select fdl1 binary");
    fc.type(Fl_Native_File_Chooser::BROWSE_FILE); fc.filter("Binary\t*.bin\nAll\t*");
    if (fc.show() == 0 && fc.filename()) fdl1_input->value(fc.filename());
}
static void pick_fdl2_cb(Fl_Widget *, void *) {
    Fl_Native_File_Chooser fc; fc.title("Select fdl2 binary");
    fc.type(Fl_Native_File_Chooser::BROWSE_FILE); fc.filter("Binary\t*.bin\nAll\t*");
    if (fc.show() == 0 && fc.filename()) fdl2_input->value(fc.filename());
}
static void pick_save_cb(Fl_Widget *, void *) {
    Fl_Native_File_Chooser fc; fc.title("Select output folder");
    fc.type(Fl_Native_File_Chooser::BROWSE_DIRECTORY);
    if (fc.show() == 0 && fc.filename()) save_input->value(fc.filename());
}
static void pick_exec_cb(Fl_Widget *, void *) {
    Fl_Native_File_Chooser fc; fc.title("Select exec binary");
    fc.type(Fl_Native_File_Chooser::BROWSE_FILE); fc.filter("Binary\t*.bin\nAll\t*");
    if (fc.show() == 0 && fc.filename()) fexec_input->value(fc.filename());
}

// ── Option callbacks ──────────────────────────────────────────────────────────

static void chk_kick_cb(Fl_Widget *, void *) {
    if (chk_kick->value()) { chk_kickto->value(0); chk_kickto->deactivate(); kickto_input->deactivate(); }
    else                   { chk_kickto->activate(); }
}
static void chk_kickto_cb(Fl_Widget *, void *) {
    if (chk_kickto->value()) { chk_kick->value(0); chk_kick->deactivate(); kickto_input->activate(); }
    else                     { chk_kick->activate(); kickto_input->deactivate(); }
}
static void chk_verbose_cb(Fl_Widget *, void *) {
    if (chk_verbose->value()) verbose_choice->activate();
    else                      verbose_choice->deactivate();
}

// ── CPU change ────────────────────────────────────────────────────────────────

static void cpu_changed_cb(Fl_Widget *, void *) {
    const char *cpu = cpu_choice->text(cpu_choice->value());
    bool custom = cpu && !strcmp(cpu, "Custom");
    if (custom) { exec_input->show(); fexec_input->show(); btn_exec->show(); }
    else        { exec_input->hide(); fexec_input->hide(); btn_exec->hide(); }
    Fl::check();
}

// ── Theme helpers ─────────────────────────────────────────────────────────────

static void apply_theme() {
    Fl::scheme("gtk+");
    Fl::background(28, 28, 28);
    Fl::background2(18, 18, 18);
    Fl::foreground(210, 210, 210);
}
static void style_input(Fl_Input *w) {
    w->color(COL_INPUT_BG); w->textcolor(COL_INPUT_FG);
    w->textfont(FL_COURIER); w->textsize(12);
    w->labelcolor(COL_FG); w->cursor_color(COL_INPUT_FG);
}
static void style_button(Fl_Button *w, Fl_Color label_col) {
    w->color(COL_WIDGET); w->labelcolor(label_col); w->box(FL_FLAT_BOX);
}
static void style_picker(Fl_Button *w) {
    w->color(fl_rgb_color(55,55,55)); w->labelcolor(COL_FG);
    w->box(FL_FLAT_BOX); w->labelsize(11);
}
static void style_check(Fl_Check_Button *w) {
    w->labelcolor(COL_FG); w->labelsize(12);
    w->color(COL_BG); w->selection_color(COL_INPUT_FG);
}

// ── Convenience: place one button in 2-col grid ───────────────────────────────

// col: 0=left, 1=right.  y is updated on col 1 (end of row).
static Fl_Button *make_btn(int col, int &y, const char *label, Fl_Color col_fg) {
    int bx = (col == 0) ? BCOL0_X : BCOL1_X;
    Fl_Button *b = new Fl_Button(bx, y, BCOL_W, BTN_H, label);
    style_button(b, col_fg);
    if (col == 1) y += BTN_H + BTN_GAP;
    return b;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main() {
    apply_theme();
    Fl::lock();

    Fl_Window *win = new Fl_Window(WIN_W, WIN_H, "spd_tool");
    win->color(COL_BG);

    int y = 10;

    // ── CPU choice ────────────────────────────────────────────────────────────
    cpu_choice = new Fl_Choice(INPUT_X, y, INPUT_W, 25, "CPU:");
    cpu_choice->color(COL_WIDGET); cpu_choice->labelcolor(COL_FG); cpu_choice->textcolor(COL_FG);
    cpu_choice->add("sc9820e"); cpu_choice->add("sc9832e"); cpu_choice->add("sc9863a");
    cpu_choice->add("ud710");   cpu_choice->add("ums312");  cpu_choice->add("ums512");
    cpu_choice->add("udx710");  cpu_choice->add("ums9230"); cpu_choice->add("ums9620");
    cpu_choice->add("ums9621"); cpu_choice->add("Custom");
    cpu_choice->callback(cpu_changed_cb); cpu_choice->value(8);
    y += ROW_H;

    // ── fdl1 ─────────────────────────────────────────────────────────────────
    fdl1_input = new Fl_Input(INPUT_X, y, INPUT_W, 24, "fdl1:");
    style_input(fdl1_input);
    { Fl_Button *b = new Fl_Button(PICK_X, y, PICK_W, 24, "..."); style_picker(b); b->callback(pick_fdl1_cb); }
    y += ROW_H;

    // ── fdl2 ─────────────────────────────────────────────────────────────────
    fdl2_input = new Fl_Input(INPUT_X, y, INPUT_W, 24, "fdl2:");
    style_input(fdl2_input);
    { Fl_Button *b = new Fl_Button(PICK_X, y, PICK_W, 24, "..."); style_picker(b); b->callback(pick_fdl2_cb); }
    y += ROW_H;

    // ── exec file (Custom only) ───────────────────────────────────────────────
    fexec_input = new Fl_Input(INPUT_X, y, INPUT_W, 24, "exec:");
    style_input(fexec_input);
    btn_exec = new Fl_Button(PICK_X, y, PICK_W, 24, "...");
    style_picker(btn_exec); btn_exec->callback(pick_exec_cb);
    fexec_input->hide(); btn_exec->hide();
    y += ROW_H;

    // ── exec addr (Custom only) ───────────────────────────────────────────────
    exec_input = new Fl_Input(INPUT_X, y, INPUT_W, 24, "addr:");
    style_input(exec_input); exec_input->hide();
    y += ROW_H;

    // ── save folder ───────────────────────────────────────────────────────────
    save_input = new Fl_Input(INPUT_X, y, INPUT_W, 24, "save:");
    style_input(save_input); save_input->value(".");
    { Fl_Button *b = new Fl_Button(PICK_X, y, PICK_W, 24, "..."); style_picker(b); b->callback(pick_save_cb); }
    y += ROW_H + GAP;

    // ── Options ───────────────────────────────────────────────────────────────
    static const int CHK_W = 90;
    static const int CTL_X = LEFT_X + CHK_W + 6;
    static const int CTL_W = LEFT_W - CHK_W - 6;

    // verbose
    chk_verbose = new Fl_Check_Button(LEFT_X, y, CHK_W, OPT_H, "verbose");
    style_check(chk_verbose); chk_verbose->callback(chk_verbose_cb);
    verbose_choice = new Fl_Choice(CTL_X, y, CTL_W, OPT_H);
    verbose_choice->color(COL_WIDGET); verbose_choice->textcolor(COL_FG); verbose_choice->labelcolor(COL_FG);
    verbose_choice->add("0 — quiet"); verbose_choice->add("1 — normal"); verbose_choice->add("2 — debug");
    verbose_choice->value(1); verbose_choice->deactivate();
    y += OPT_H + 4;

    // kick
    chk_kick = new Fl_Check_Button(LEFT_X, y, LEFT_W, OPT_H, "kick  (boot_diag -> cali_diag -> dl_diag)");
    style_check(chk_kick); chk_kick->callback(chk_kick_cb);
    y += OPT_H + 4;

    // kickto
    chk_kickto = new Fl_Check_Button(LEFT_X, y, CHK_W, OPT_H, "kickto");
    style_check(chk_kickto); chk_kickto->callback(chk_kickto_cb);
    kickto_input = new Fl_Input(CTL_X, y, CTL_W, OPT_H);
    kickto_input->color(COL_INPUT_BG); kickto_input->textcolor(COL_INPUT_FG);
    kickto_input->textfont(FL_COURIER); kickto_input->textsize(12);
    kickto_input->cursor_color(COL_INPUT_FG); kickto_input->value("2");
    kickto_input->deactivate();
    y += OPT_H + 4;

    // slot selector — shared between set_active and write_parts
    // label on left, choice on right
    static const int SLOT_LABEL_W = 36;
    Fl_Box *slot_label = new Fl_Box(LEFT_X, y, SLOT_LABEL_W, OPT_H, "slot:");
    slot_label->labelcolor(COL_FG); slot_label->labelsize(12); slot_label->align(FL_ALIGN_LEFT|FL_ALIGN_INSIDE);
    slot_choice = new Fl_Choice(LEFT_X + SLOT_LABEL_W + 4, y, LEFT_W - SLOT_LABEL_W - 4, OPT_H);
    slot_choice->color(COL_WIDGET); slot_choice->textcolor(COL_FG); slot_choice->labelcolor(COL_FG);
    slot_choice->add("auto"); slot_choice->add("a"); slot_choice->add("b");
    slot_choice->value(0);
    y += OPT_H + 4;

    // reset after op checkbox — spans full width
    chk_reset_after = new Fl_Check_Button(LEFT_X, y, LEFT_W, OPT_H, "reset device after operation");
    style_check(chk_reset_after);
    chk_reset_after->labelcolor(COL_AMBER);   // amber to hint it causes a reboot
    y += OPT_H + GAP + 4;

    // ── 2-column button grid ──────────────────────────────────────────────────
    // Left col = read / write ops (green/amber)
    // Right col = erase / util / danger (amber/red/muted)
    //
    // Row layout (left | right):
    //  Dump Full EMMC     | Erase Partition
    //  Dump Full Lite     | Erase All !!
    //  Dump Partitions    | Set Active Slot
    //  Flash Partitions   | Write Parts
    //  Flash Full EMMC    | Reset
    //  (full-width)       | Clear Log

    action_btns[0]  = make_btn(0, y, "Dump Full EMMC",  COL_GREEN);
    action_btns[5]  = make_btn(1, y, "Erase Partition",  COL_AMBER);

    action_btns[1]  = make_btn(0, y, "Dump Full Lite",   COL_GREEN);
    action_btns[6]  = make_btn(1, y, "Erase All !!",     COL_RED);

    action_btns[2]  = make_btn(0, y, "Dump Partitions",  COL_GREEN);
    action_btns[7]  = make_btn(1, y, "Set Active Slot",  COL_BLUE);

    action_btns[3]  = make_btn(0, y, "Flash Partitions", COL_AMBER);
    action_btns[8]  = make_btn(1, y, "Write Parts",      COL_AMBER);

    action_btns[4]  = make_btn(0, y, "Flash Full EMMC",  COL_RED);
    action_btns[9]  = make_btn(1, y, "Reset",            COL_MUTED);

    // clear log spans full width
    action_btns[10] = new Fl_Button(LEFT_X, y, LEFT_W, BTN_H, "Clear Log");
    style_button(action_btns[10], COL_MUTED);

    action_btns[0]->callback(dump_all_cb);
    action_btns[1]->callback(dump_all_lite_cb);
    action_btns[2]->callback(dump_part_cb);
    action_btns[3]->callback(flash_part_cb);
    action_btns[4]->callback(flash_all_cb);
    action_btns[5]->callback(erase_part_cb);
    action_btns[6]->callback(erase_all_cb);
    action_btns[7]->callback(set_active_cb);
    action_btns[8]->callback(write_parts_cb);
    action_btns[9]->callback(reset_cb);
    action_btns[10]->callback(clear_cb);

    // ── Log output ────────────────────────────────────────────────────────────
    log_buf = new Fl_Text_Buffer();
    output  = new Fl_Text_Display(LOG_X, 10, LOG_W, LOG_H);
    output->buffer(log_buf);
    output->color(COL_LOG_BG); output->textcolor(COL_LOG_FG);
    output->textfont(FL_COURIER); output->textsize(12);

    win->end();
    win->show();

    Fl::add_timeout(0.1, setup_spd_dump_cb);
    return Fl::run();
}
