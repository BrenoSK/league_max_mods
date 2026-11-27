#include <unistd.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cctype>
#include <cmath>
#include <string>
#include <atomic>
#include <pthread.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "LMX", __VA_ARGS__)

#ifdef AS_INJECTOR
/* ================= INJECTOR ================= */
#include <vector>
#include <link.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <asm/ptrace.h>

static uint64_t g_scratch, g_brk;

static bool regs_get(int tid, user_pt_regs* r) {
    iovec io{r, sizeof(*r)};
    return ptrace(PTRACE_GETREGSET, tid, (void*) NT_PRSTATUS, &io) == 0;
}
static bool regs_set(int tid, user_pt_regs* r) {
    iovec io{r, sizeof(*r)};
    return ptrace(PTRACE_SETREGSET, tid, (void*) NT_PRSTATUS, &io) == 0;
}
static bool poke(int tid, uint64_t a, const void* d, size_t len) {
    const uint64_t* p = (const uint64_t*) d;
    for (size_t i = 0; i < len / 8; i++)
        if (ptrace(PTRACE_POKEDATA, tid, (void*) (a + i * 8), (void*) p[i]) < 0) return false;
    return true;
}
static uint64_t base_of(int pid, const char* name) {
    char p[64], l[512];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE* f = fopen(p, "r");
    if (!f) return 0;
    uint64_t o = 0;
    while (fgets(l, sizeof(l), f)) {
        if (!strstr(l, name)) continue;
        unsigned long s, e, off;
        if (sscanf(l, "%lx-%lx %*s %lx", &s, &e, &off) == 3) { o = s - off; break; }
    }
    fclose(f);
    return o;
}
static uint64_t rcall(int tid, uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    user_pt_regs save{}, r{};
    if (!regs_get(tid, &save)) return 0;
    r = save;
    r.regs[0] = a0; r.regs[1] = a1; r.regs[2] = a2;
    r.regs[3] = a3; r.regs[4] = a4; r.regs[5] = a5;
    r.regs[30] = g_brk; r.sp = g_scratch + 0xF00; r.pc = fn;
    if (!regs_set(tid, &r)) return 0;
    ptrace(PTRACE_CONT, tid, 0, 0);
    int st; waitpid(tid, &st, __WALL);
    user_pt_regs a{};
    uint64_t ret = 0;
    if (regs_get(tid, &a)) ret = a.regs[0];
    regs_set(tid, &save);
    return ret;
}

int main(int argc, char** argv) {
    if (argc < 3) { LOGI("uso: injector <pid> <lib>"); return 1; }
    int pid = atoi(argv[1]);
    std::vector<int> tids;
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/task", pid);
    FILE* f = fopen(p, "r");
    if (!f) { LOGI("sem proc"); return 1; }
    int t;
    while (fscanf(f, "%d", &t) == 1) tids.push_back(t);
    fclose(f);
    for (int tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, 0, 0) < 0) LOGI("attach fail %d", tid);
        int st; waitpid(tid, &st, __WALL);
    }
    void* libc = dlopen("libc.so", RTLD_NOW);
    Dl_info di{};
    dladdr((void*) dlsym(libc, "mmap"), &di);
    uint64_t om = (uint64_t) dlsym(libc, "mmap") - (uint64_t) di.dli_fbase;
    dladdr((void*) dlsym(libc, "dlopen"), &di);
    uint64_t od = (uint64_t) dlsym(libc, "dlopen") - (uint64_t) di.dli_fbase;
    uint64_t base = base_of(pid, "/libc.so");
    LOGI("libc %p", (void*) base);
    g_scratch = rcall(tids[0], base + om, 0, 0x1000,
                      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, (uint64_t) -1, 0);
    if (g_scratch && g_scratch != (uint64_t) -1) {
        g_brk = g_scratch + 0x100;
        uint64_t brk = 0xd4200000ULL;
        poke(tids[0], g_brk, &brk, 8);
        size_t len = strlen(argv[2]) + 1;
        poke(tids[0], g_scratch + 0x200, argv[2], (len + 7) & ~7UL);
        uint64_t h = rcall(tids[0], base + od, g_scratch + 0x200, RTLD_NOW | RTLD_GLOBAL, 0, 0, 0, 0);
        LOGI("dlopen %p", (void*) h);
    }
    for (int tid : tids) ptrace(PTRACE_DETACH, tid, 0, 0);
    return 0;
}

#else
/* ================= LIB ================= */
#include <link.h>
#include <elf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>

/* ---------- assinaturas il2cpp ---------- */
typedef void* (*f_void_v)();
typedef void* (*f_v_v)(void*);
typedef void** (*f_asm)(void*, size_t*);
typedef void* (*f_v_sz)(void*, size_t);
typedef size_t (*f_sz_v)(void*);
typedef void* (*f_cfn)(void*, const char*, const char*);
typedef void** (*f_fields)(void*, void**);
typedef void* (*f_meth)(void*, const char*, int);
typedef const char* (*f_str_v)(void*);
typedef void (*f_fv)(void*, void*, void*);
typedef void (*f_fs)(void*, void*);
typedef void (*f_inv)(void*, void*, void**, void**);
typedef char* (*f_addr)(void*, size_t, size_t);
typedef uint32_t (*f_flags)(void*);

static f_void_v domain_get;
static f_v_v thread_attach, assembly_image, field_type, object_class;
static f_asm get_assemblies;
static f_v_sz image_class;
static f_sz_v image_class_count, array_len;
static f_cfn class_from_name;
static f_fields class_fields;
static f_meth class_get_method;
static f_str_v image_name, field_name, type_name, class_name;
static f_fv field_value;
static f_fs field_static_get;
static f_inv runtime_invoke;
static f_addr array_addr;
static f_flags field_flags;

static void* transform_cls;
static void* camera_cls;
static void* cam_obj;

static void* best_cls;
static void* hp_field;
static void* team_field;
static void* local_field;
static void* tr_field;
static int off_tr = -1;
static void* list_field;
static int list_is_array;
static void* local_obj;
static int local_team;

/* ---------- estado ---------- */
struct Ent { float h[3], f[3]; int hp; float dist; };
static Ent snap[64];
static std::atomic<int> snap_n{0};
static float cam_pos[3];
static int g_w = 0, g_h = 0;
static float g_vp[16];
static std::atomic<bool> g_vp_ok{false};
static std::atomic<int> g_esp{1}, g_aim{0}, g_fov{25};
static int g_fd = -1;

static void status(const char* s) {
    int fd = g_fd;
    if (fd < 0) return;
    char b[300];
    int n = snprintf(b, sizeof(b), "S|%s\n", s);
    if (write(fd, b, n) < 0) { }
}

/* ---------- config ---------- */
static void* sock_thread(void*) {
    for (;;) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un a{};
        a.sun_family = AF_UNIX;
        a.sun_path[0] = 0;
        strcpy(a.sun_path + 1, "leaguemax_cfg");
        if (fd < 0 || connect(fd, (sockaddr*) &a, sizeof(a))) { close(fd); sleep(1); continue; }
        g_fd = fd;
        char b[256], acc[128];
        int an = 0;
        for (;;) {
            ssize_t n = read(fd, b, sizeof(b));
            if (n <= 0) break;
            for (ssize_t i = 0; i < n; i++) {
                if (b[i] == '\n') {
                    acc[an] = 0; an = 0;
                    const char* e = strchr(acc, '=');
                    if (!e) continue;
                    int v = atoi(e + 1);
                    if (!strncmp(acc, "esp", 3)) g_esp = v;
                    else if (!strncmp(acc, "aim", 3)) g_aim = v;
                    else if (!strncmp(acc, "fov", 3)) g_fov = v;
                } else if (an < 120) acc[an++] = b[i];
            }
        }
        g_fd = -1;
        close(fd);
        sleep(1);
    }
    return nullptr;
}

/* ---------- descoberta ---------- */
static int ieq(const char* h, const char* n) {
    for (; *h && *n; h++, n++) if (tolower(*h) != tolower(*n)) return 0;
    return *n == 0;
}
static bool has(const char* h, const char* n) {
    if (!h || !n) return false;
    for (; *h; h++) if (ieq(h, n)) return true;
    return false;
}

static bool il2_init() {
    void* h = dlopen("libil2cpp.so", RTLD_NOLOAD);
    if (!h) { status("libil2cpp nao carregada"); return false; }
#define R(v, n) v = (decltype(v)) dlsym(h, "il2cpp_" #n)
    R(domain_get, domain_get);
    R(thread_attach, thread_attach);
    R(get_assemblies, domain_get_assemblies);
    R(assembly_image, assembly_get_image);
    R(image_name, image_get_name);
    R(image_class, image_get_class);
    R(image_class_count, image_get_class_count);
    R(class_from_name, class_from_name);
    R(class_fields, class_get_fields);
    R(field_name, field_get_name);
    R(field_type, field_get_type);
    R(field_flags, field_get_flags);
    R(field_value, field_get_value);
    R(field_static_get, field_static_get_value);
    R(type_name, type_get_name);
    R(class_get_method, class_get_method_from_name);
    R(class_name, class_get_name);
    R(object_class, object_get_class);
    R(runtime_invoke, runtime_invoke);
    R(array_len, array_length);
    R(array_addr, array_addr_with_size);
#undef R
    if (!domain_get || !class_from_name || !runtime_invoke) {
        status("exports ausentes");
        return false;
    }
    thread_attach(domain_get());
    return true;
}

static void* find_image(const char* asm_name) {
    size_t n = 0;
    void** a = get_assemblies(domain_get(), &n);
    if (!a) return nullptr;
    for (size_t i = 0; i < n; i++) {
        void* img = assembly_image(a[i]);
        const char* nm = image_name(img);
        if (nm && strcmp(nm, asm_name) == 0) return img;
    }
    return nullptr;
}

static int score(void* k) {
    int s = 0;
    void* it = nullptr;
    void* f;
    while ((f = (void*) class_fields(k, &it))) {
        const char* n = field_name(f);
        void* t = field_type(f);
        const char* tn = t ? type_name(t) : nullptr;
        if (tn && has(tn, "Transform")) { s += 4; if (!tr_field) { tr_field = f; off_tr = (int) 0; } }
        if (n && (has(n, "hp") || has(n, "health") || has(n, "vida"))) { s += 3; if (!hp_field) hp_field = f; }
        if (n && has(n, "team")) { s += 2; if (!team_field) team_field = f; }
        if (n && (has(n, "local") || has(n, "mine"))) { s += 2; if (!local_field) local_field = f; }
    }
    return s;
}

static void discover() {
    void* img = find_image("Assembly-CSharp.dll");
    if (!img) { status("Assembly-CSharp nao achada"); return; }
    size_t cnt = image_class_count(img);
    status("varrendo classes...");

    int best = 0;
    for (size_t i = 0; i < cnt; i++) {
        void* k = image_class(img, i);
        if (!k) continue;
        const char* n = class_name(k);
        if (!n || !has(n, "player")) continue;

        void *hpf = nullptr, *tmf = nullptr, *lcf = nullptr, *trf = nullptr;
        void* save_tr = tr_field; tr_field = nullptr;
        void* save_hp = hp_field; hp_field = nullptr;
        void* save_tm = team_field; team_field = nullptr;
        void* save_lc = local_field; local_field = nullptr;
        int s = score(k);
        trf = tr_field; hpf = hp_field; tmf = team_field; lcf = local_field;

        if (trf && s > best) {
            best = s; best_cls = k;
            tr_field = trf; hp_field = hpf; team_field = tmf; local_field = lcf;
        } else {
            tr_field = save_tr; hp_field = save_hp;
            team_field = save_tm; local_field = save_lc;
        }
    }
    if (!best_cls) { status("nenhuma classe Player com Transform"); return; }
    status((std::string("classe: ") + class_name(best_cls)).c_str());

    for (size_t i = 0; i < cnt && !list_field; i++) {
        void* k = image_class(img, i);
        if (!k) continue;
        void* it = nullptr;
        void* f;
        while ((f = (void*) class_fields(k, &it))) {
            if (!(field_flags(f) & 0x10)) continue;
            void* t = field_type(f);
            const char* tn = t ? type_name(t) : nullptr;
            if (!tn || !has(tn, class_name(best_cls))) continue;
            list_field = f;
            list_is_array = strstr(tn, "[]") != nullptr;
            break;
        }
    }
    status(list_field ? "lista de players OK" : "sem lista de players");

    void* core = find_image("UnityEngine.CoreModule.dll");
    if (core) {
        transform_cls = class_from_name(core, "UnityEngine", "Transform");
        camera_cls = class_from_name(core, "UnityEngine", "Camera");
        if (camera_cls) {
            void* m = class_get_method(camera_cls, "get_main", 0);
            if (m) runtime_invoke(m, nullptr, nullptr, &cam_obj);
        }
    }
    status(transform_cls ? "engine OK" : "engine stripped");
}

static bool wpos(void* obj, float out[3]) {
    if (!obj || !transform_cls) return false;
    void* tr = nullptr;
    if (tr_field) field_value(obj, tr_field, &tr);
    if (!tr) {
        void* cls = object_class(obj);
        if (cls) {
            void* m = class_get_method(cls, "get_transform", 0);
            if (m) runtime_invoke(m, obj, nullptr, &tr);
        }
    }
    if (!tr) return false;
    void* m = class_get_method(transform_cls, "get_position", 0);
    if (!m) return false;
    struct V3 { float x, y, z; } v{};
    runtime_invoke(m, tr, nullptr, &v);
    out[0] = v.x; out[1] = v.y; out[2] = v.z;
    return true;
}

static void scan() {
    snap_n = 0;
    if (!best_cls || !list_field) return;
    void* arr = nullptr;
    field_static_get(list_field, &arr);
    if (!arr) return;
    int n = (int) array_len(arr);
    if (n > 64) n = 64;
    int k = 0;
    for (int i = 0; i < n; i++) {
        void* o = *(void**) array_addr(arr, 8, i);
        if (!o) continue;
        if (local_field) {
            unsigned char b = 0;
            field_value(o, local_field, &b);
            if (b) {
                local_obj = o;
                if (team_field) field_value(o, team_field, &local_team);
                continue;
            }
        }
        if (team_field && local_team) {
            int tm = 0;
            field_value(o, team_field, &tm);
            if (tm == local_team) continue;
        }
        float f[3];
        if (!wpos(o, f)) continue;
        Ent& e = snap[k];
        e.f[0] = f[0]; e.f[1] = f[1]; e.f[2] = f[2];
        e.h[0] = f[0]; e.h[1] = f[1] + 1.55f; e.h[2] = f[2];
        e.hp = 100;
        if (hp_field) {
            int hp = 0;
            field_value(o, hp_field, &hp);
            e.hp = (hp > 0 && hp <= 200) ? hp : 100;
        }
        float dx = f[0] - cam_pos[0], dy = f[1] - cam_pos[1], dz = f[2] - cam_pos[2];
        e.dist = sqrtf(dx * dx + dy * dy + dz * dz);
        k++;
    }
    snap_n = k;
}

static void* work_thread(void*) {
    sleep(2);
    if (!il2_init()) return nullptr;
    discover();
    for (;;) {
        if (cam_obj) {
            float c[3];
            if (wpos(cam_obj, c)) memcpy(cam_pos, c, sizeof(c));
        } else if (local_obj) {
            float c[3];
            if (wpos(local_obj, c)) memcpy(cam_pos, c, sizeof(c));
        }
        scan();
        usleep(33000);
    }
    return nullptr;
}

/* ---------- GOT hook ---------- */
struct Ctx { const char* sym; void* fn; int hits; };
static int visit(dl_phdr_info* i, size_t, void* raw) {
    Ctx* c = (Ctx*) raw;
    if (!i->dlpi_name || !i->dlpi_name[0]) return 0;
    const ElfW(Dyn)* d = nullptr;
    for (int k = 0; k < i->dlpi_phnum; k++)
        if (i->dlpi_phdr[k].p_type == PT_DYNAMIC)
            d = (const ElfW(Dyn)*) (i->dlpi_addr + i->dlpi_phdr[k].p_vaddr);
    if (!d) return 0;
    ElfW(Addr) jm = 0, st = 0, sr = 0;
    size_t sz = 0; long rl = 0;
    for (; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_JMPREL) jm = d->d_un.d_ptr;
        else if (d->d_tag == DT_PLTRELSZ) sz = d->d_un.d_val;
        else if (d->d_tag == DT_SYMTAB) st = d->d_un.d_ptr;
        else if (d->d_tag == DT_STRTAB) sr = d->d_un.d_ptr;
        else if (d->d_tag == DT_PLTREL) rl = (long) d->d_un.d_val;
    }
    if (!jm || !sz || !st || !sr || rl != DT_RELA) return 0;
    auto* r = (ElfW(Rela)*) jm;
    for (size_t k = 0; k < sz / sizeof(ElfW(Rela)); k++) {
        if (ELF64_R_TYPE(r[k].r_info) != R_AARCH64_JUMP_SLOT) continue;
        const char* n = (const char*) (sr + ((ElfW(Sym)*) st)[ELF64_R_SYM(r[k].r_info)].st_name);
        if (strcmp(n, c->sym)) continue;
        void** slot = (void**) (i->dlpi_addr + r[k].r_offset);
        uintptr_t pg = (uintptr_t) slot & ~0xFFFUL;
        mprotect((void*) pg, 0x1000, PROT_READ | PROT_WRITE);
        *slot = c->fn;
        mprotect((void*) pg, 0x1000, PROT_READ);
        c->hits++;
    }
    return 0;
}
static int got_hook(const char* s, void* f) {
    Ctx c{s, f, 0};
    dl_iterate_phdr(visit, &c);
    return c.hits;
}

/* ---------- render ---------- */
static const char* VS = "attribute vec2 a;uniform vec2 r;void main(){vec2 p=a/r*2.0-1.0;gl_Position=vec4(p.x,-p.y,0.0,1.0);}";
static const char* FS = "precision mediump float;uniform vec4 c;void main(){gl_FragColor=c;}";
static GLuint prog, vbo, uRes, uCol;
static float V[16384 * 2];
static int vn;

static GLuint mk(GLenum t, const char* s) {
    GLuint o = glCreateShader(t);
    glShaderSource(o, 1, &s, nullptr);
    glCompileShader(o);
    return o;
}
static void seg(float x1, float y1, float x2, float y2) {
    if (vn > 16300) return;
    V[vn * 2] = x1; V[vn * 2 + 1] = y1; vn++;
    V[vn * 2] = x2; V[vn * 2 + 1] = y2; vn++;
}
static bool w2s(const float w[3], float* sx, float* sy) {
    if (!g_vp_ok) return false;
    float x = g_vp[0] * w[0] + g_vp[4] * w[1] + g_vp[8] * w[2] + g_vp[12];
    float y = g_vp[1] * w[0] + g_vp[5] * w[1] + g_vp[9] * w[2] + g_vp[13];
    float z = g_vp[3] * w[0] + g_vp[7] * w[1] + g_vp[11] * w[2] + g_vp[15];
    if (z <= 0.001f) return false;
    *sx = (x / z * 0.5f + 0.5f) * g_w;
    *sy = (1.f - (y / z * 0.5f + 0.5f)) * g_h;
    return true;
}
static void render() {
    if (!prog) return;
    float cx = g_w * .5f, cy = g_h * .5f;
    seg(cx - 14, cy, cx + 14, cy);
    seg(cx, cy - 14, cx, cy + 14);
    if (g_aim) {
        float r = (g_fov / 90.f) * (g_h * .5f);
        for (int i = 0; i < 56; i++) {
            float a1 = 6.2831853f * i / 56, a2 = 6.2831853f * (i + 1) / 56;
            seg(cx + cosf(a1) * r, cy + sinf(a1) * r, cx + cosf(a2) * r, cy + sinf(a2) * r);
        }
    }
    if (g_esp) {
        int n = snap_n;
        for (int i = 0; i < n; i++) {
            float hx, hy, fx, fy;
            if (!w2s(snap[i].h, &hx, &hy)) continue;
            if (!w2s(snap[i].f, &fx, &fy)) continue;
            float hh = fy - hy;
            if (hh < 4) continue;
            float wd = hh * 0.42f;
            seg(hx - wd, hy, hx + wd, hy);
            seg(hx - wd, fy, hx + wd, fy);
            seg(hx - wd, hy, hx - wd, fy);
            seg(hx + wd, hy, hx + wd, fy);
            float hb = fy - (hh * snap[i].hp / 100.f);
            seg(hx - wd - 5, hb, hx - wd - 5, fy);
        }
    }
    glViewport(0, 0, g_w, g_h);
    glDisable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glUseProgram(prog);
    glUniform2f(uRes, (float) g_w, (float) g_h);
    glUniform4f(uCol, .13f, .85f, .35f, .9f);
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glBufferData(GL_ARRAY_BUFFER, vn * 8, V, GL_DYNAMIC_DRAW);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 8, nullptr);
    glDrawArrays(GL_LINES, 0, vn);
    glDisableVertexAttribArray(0);
}
static void setup(int w, int h) {
    prog = glCreateProgram();
    glAttachShader(prog, mk(GL_VERTEX_SHADER, VS));
    glAttachShader(prog, mk(GL_FRAGMENT_SHADER, FS));
    glBindAttribLocation(prog, 0, "a");
    glLinkProgram(prog);
    uRes = glGetUniformLocation(prog, "r");
    uCol = glGetUniformLocation(prog, "c");
    glGenBuffers(1, &vbo);
    g_w = w; g_h = h;
}

static EGLBoolean (*orig_swap)(EGLDisplay, EGLSurface);
static EGLBoolean hook_swap(EGLDisplay d, EGLSurface s) {
    if (!prog) {
        EGLint w = 0, h = 0;
        eglQuerySurface(d, s, EGL_WIDTH, &w);
        eglQuerySurface(d, s, EGL_HEIGHT, &h);
        if (w > 0) setup(w, h);
    }
    vn = 0;
    render();
    return orig_swap(d, s);
}
static void (*orig_um4)(GLint, GLsizei, GLboolean, const GLfloat*);
static void hook_um4(GLint l, GLsizei c, GLboolean t, const GLfloat* m) {
    if (m && c == 1 && fabsf(m[11] + 1.f) < .02f && fabsf(m[15]) < .02f) {
        memcpy(g_vp, m, sizeof(g_vp));
        g_vp_ok = true;
    }
    orig_um4(l, c, t, m);
}

__attribute__((constructor)) static void boot() {
    LOGI("injetada %d", getpid());
    pthread_t t;
    pthread_create(&t, nullptr, [](void*) -> void* {
        sleep(