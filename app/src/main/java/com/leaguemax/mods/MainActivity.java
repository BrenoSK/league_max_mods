package com.leaguemax.mods;

import android.app.*;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.Uri;
import android.os.*;
import android.provider.Settings;
import android.view.*;
import android.widget.*;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class MainActivity extends Activity {

    static final String TARGET = "com.wsoficialzin.battleroyale";
    static final String DIR = "/data/local/tmp/lmx";

    private TextView log;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.VERTICAL);
        r.setPadding(40, 80, 40, 40);
        r.setBackgroundColor(0xFF0B0F14);

        log = new TextView(this);
        log.setTextColor(0xFF9CA3AF);
        log.setTextSize(12);
        log.setText("alvo: " + TARGET);
        r.addView(log, new LinearLayout.LayoutParams(-1, 0, 1f));

        Button go = new Button(this);
        go.setText("INICIAR");
        go.setOnClickListener(v -> iniciar());
        r.addView(go);

        Button stop = new Button(this);
        stop.setText("PARAR");
        stop.setOnClickListener(v -> stopService(new Intent(this, Overlay.class)));
        r.addView(stop);

        setContentView(r);
    }

    private void log(String s) { ui.post(() -> log.append("\n" + s)); }

    private void iniciar() {
        if (!Settings.canDrawOverlays(this)) {
            startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName())));
            log("libere sobrepor apps");
            return;
        }
        startForegroundService(new Intent(this, Overlay.class));
        new Thread(this::injetar).start();
    }

    private String sh(String cmd) {
        StringBuilder o = new StringBuilder();
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l;
            while ((l = r.readLine()) != null) o.append(l).append('\n');
            p.waitFor();
        } catch (Exception e) { o.append("ERR ").append(e.getMessage()); }
        return o.toString().trim();
    }

    private void injetar() {
        if (!sh("id -u").startsWith("0")) { log("sem root"); return; }
        sh("setenforce 0");
        String pid = sh("pidof " + TARGET).trim();
        if (!pid.matches("[0-9]+")) { log("jogo fechado"); return; }
        log("pid " + pid);
        String nat = getApplicationInfo().nativeLibraryDir;
        log(sh("mkdir -p " + DIR + " && cp " + nat + "/libinjector.so " + nat + "/libcore.so " + DIR + "/ && chmod 755 " + DIR + "/*"));
        log(sh(DIR + "/libinjector.so " + pid + " " + DIR + "/libcore.so"));
        log("injetado");
    }

    public static class Overlay extends Service {

        private WindowManager wm;
        private View panel;
        private WindowManager.LayoutParams lp;
        private LocalSocket client;
        private LocalServerSocket server;
        private volatile boolean alive = true;
        private int aim = 0, fov = 25, esp = 1;
        private TextView status;

        @Override public void onCreate() {
            super.onCreate();
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel("x", "lmx", NotificationManager.IMPORTANCE_LOW));
            startForeground(1, new Notification.Builder(this, "x")
                    .setContentTitle("LMX").setSmallIcon(android.R.drawable.ic_menu_compass).build());
            wm = (WindowManager) getSystemService(WINDOW_SERVICE);
            montar();
            new Thread(this::servidor).start();
        }

        private void servidor() {
            try {
                server = new LocalServerSocket("leaguemax_cfg");
                while (alive) {
                    client = server.accept();
                    send("esp=" + esp + "\naim=" + aim + "\nfov=" + fov + "\n");
                    new Thread(() -> {
                        byte[] b = new byte[256];
                        StringBuilder sb = new StringBuilder();
                        try {
                            for (;;) {
                                int n = client.getInputStream().read(b);
                                if (n <= 0) break;
                                for (int i = 0; i < n; i++) {
                                    if (b[i] == '\n') {
                                        String s = sb.toString();
                                        sb.setLength(0);
                                        if (s.startsWith("S|")) {
                                            String t = s.substring(2);
                                            ui.post(() -> status.setText(t));
                                        }
                                    } else sb.append((char) b[i]);
                                }
                            }
                        } catch (Exception ignored) { }
                    }).start();
                }
            } catch (Exception ignored) { }
        }

        private void send(String s) {
            LocalSocket c = client;
            if (c == null) return;
            try {
                c.getOutputStream().write(s.getBytes(StandardCharsets.UTF_8));
                c.getOutputStream().flush();
            } catch (Exception e) { client = null; }
        }

        private void montar() {
            LinearLayout col = new LinearLayout(this);
            col.setOrientation(LinearLayout.VERTICAL);
            col.setPadding(28, 18, 28, 22);
            GradientDrawable bg = new GradientDrawable();
            bg.setColor(0xF00B0F14);
            bg.setCornerRadius(26);
            bg.setStroke(2, 0xFF22C55E);
            col.setBackground(bg);

            TextView h = new TextView(this);
            h.setText("LMX  ::  arraste");
            h.setTextColor(0xFF22C55E);
            h.setTextSize(12);
            col.addView(h);

            status = new TextView(this);
            status.setText("aguardando lib...");
            status.setTextColor(0xFF64748B);
            status.setTextSize(10);
            col.addView(status);

            Switch e = new Switch(this);
            e.setText("ESP");
            e.setTextColor(0xFFE2E8F0);
            e.setChecked(true);
            e.setOnCheckedChangeListener((v, b) -> { esp = b ? 1 : 0; send("esp=" + esp + "\n"); });
            col.addView(e);

            Switch a = new Switch(this);
            a.setText("Aimbot");
            a.setTextColor(0xFFE2E8F0);
            a.setOnCheckedChangeListener((v, b) -> { aim = b ? 1 : 0; send("aim=" + aim + "\n"); });
            col.addView(a);

            SeekBar sb = new SeekBar(this);
            sb.setMax(90);
            sb.setProgress(fov);
            sb.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
                public void onProgressChanged(SeekBar s, int p, boolean u) { fov = p; send("fov=" + p + "\n"); }
                public void onStartTrackingTouch(SeekBar s) { }
                public void onStopTrackingTouch(SeekBar s) { }
            });
            col.addView(sb);

            Button c = new Button(this);
            c.setText("FECHAR");
            c.setOnClickListener(v -> stopSelf());
            col.addView(c);

            lp = new WindowManager.LayoutParams(420, -2,
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE, PixelFormat.TRANSLUCENT);
            lp.gravity = Gravity.TOP | Gravity.START;
            lp.x = 40; lp.y = 100;

            h.setOnTouchListener(new View.OnTouchListener() {
                float dx, dy; int x0, y0;
                public boolean onTouch(View v, MotionEvent ev) {
                    if (ev.getActionMasked() == MotionEvent.ACTION_DOWN) {
                        dx = ev.getRawX(); dy = ev.getRawY(); x0 = lp.x; y0 = lp.y; return true;
                    }
                    if (ev.getActionMasked() == MotionEvent.ACTION_MOVE) {
                        lp.x = (int) (x0 + ev.getRawX() - dx);
                        lp.y = (int) (y0 + ev.getRawY() - dy);
                        wm.updateViewLayout(panel, lp);
                        return true;
                    }
                    return false;
                }
            });

            panel = col;
            wm.addView(panel, lp);
        }

        @Override public void onDestroy() {
            alive = false;
            try { if (server != null) server.close(); } catch (Exception ignored) { }
            try { if (panel != null) wm.removeView(panel); } catch (Exception ignored) { }
            super.onDestroy();
        }

        @Override public IBinder onBind(Intent i) { return null; }
    }
}