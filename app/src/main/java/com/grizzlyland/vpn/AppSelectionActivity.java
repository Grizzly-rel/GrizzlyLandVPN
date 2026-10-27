package com.grizzlyland.vpn;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Экран выбора приложений, для которых работает VPN (per-app),
 * аналогично OpenVPN for Android.
 */
public class AppSelectionActivity extends Activity {

    private static class AppInfo {
        String label;
        String pkg;
        Drawable icon;
    }

    private final List<AppInfo> apps = new ArrayList<>();
    private final Set<String> selected = new HashSet<>();
    private ConfigManager config;
    private AppAdapter adapter;
    private ListView list;
    private TextView hint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        L10n.init(this);
        config = new ConfigManager(this);
        selected.addAll(config.getAllowedApps());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(20, 20, 20, 20);

        TextView title = new TextView(this);
        title.setText(getString(R.string.title_apps));
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Явный режим «VPN для всего телефона»: туннель без allowed-фильтра,
        // per-app список не действует (серый и некликабельный).
        Switch allAppsSwitch = new Switch(this);
        allAppsSwitch.setText(getString(R.string.switch_all_apps));
        allAppsSwitch.setTextSize(16);
        allAppsSwitch.setPadding(0, 20, 0, 4);
        allAppsSwitch.setChecked(config.getVpnAllApps());
        allAppsSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                config.setVpnAllApps(isChecked);
                updateListEnabled();
                // Пересоздаём туннель с новым фильтром (реконнект, если подключён).
                GrizzlyLandVpnService.requestApply(AppSelectionActivity.this);
            }
        });
        root.addView(allAppsSwitch);

        hint = new TextView(this);
        hint.setTextSize(13);
        hint.setPadding(0, 0, 0, 8);
        root.addView(hint);

        list = new ListView(this);
        adapter = new AppAdapter();
        list.setAdapter(adapter);
        root.addView(list, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
        loadApps();
        updateListEnabled();
    }

    /** Серый/некликабельный список в режиме «VPN для всего телефона». */
    private void updateListEnabled() {
        boolean all = config.getVpnAllApps();
        hint.setText(all
                ? getString(R.string.hint_all_on)
                : getString(R.string.hint_all_off));
        list.setAlpha(all ? 0.35f : 1f);
        adapter.notifyDataSetChanged();
    }

    private void loadApps() {
        apps.clear();
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> installed = pm.getInstalledApplications(
                PackageManager.GET_META_DATA);
        for (ApplicationInfo ai : installed) {
            if (pm.getLaunchIntentForPackage(ai.packageName) == null) {
                continue; // только приложения с лаунчером
            }
            if (ai.packageName.equals(getPackageName())) {
                continue;
            }
            AppInfo info = new AppInfo();
            info.pkg = ai.packageName;
            info.label = pm.getApplicationLabel(ai).toString();
            info.icon = pm.getApplicationIcon(ai);
            apps.add(info);
        }
        // Сортируем список приложений по алфавиту (по отображаемому имени),
        // с учётом локали и регистра (A-Z перед a-z, как в обычных лаунчерах).
        final Collator collator = Collator.getInstance();
        Collections.sort(apps, new Comparator<AppInfo>() {
            @Override
            public int compare(AppInfo a, AppInfo b) {
                return collator.compare(a.label, b.label);
            }
        });
        adapter.notifyDataSetChanged();
    }

    private class AppAdapter extends BaseAdapter {

        @Override
        public int getCount() {
            return apps.size();
        }

        @Override
        public Object getItem(int position) {
            return apps.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(final int position, View convertView, ViewGroup parent) {
            LinearLayout row;
            if (convertView == null) {
                row = new LinearLayout(AppSelectionActivity.this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setPadding(16, 16, 16, 16);
                row.setGravity(Gravity.CENTER_VERTICAL);

                ImageView icon = new ImageView(AppSelectionActivity.this);
                icon.setId(100);
                row.addView(icon, new LinearLayout.LayoutParams(56, 56));

                TextView label = new TextView(AppSelectionActivity.this);
                label.setId(101);
                label.setTextSize(16);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                        LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
                lp.setMargins(16, 0, 0, 0);
                row.addView(label, lp);

                CheckBox cb = new CheckBox(AppSelectionActivity.this);
                cb.setId(102);
                row.addView(cb);
            } else {
                row = (LinearLayout) convertView;
            }

            final AppInfo info = apps.get(position);
            ((ImageView) row.findViewById(100)).setImageDrawable(info.icon);
            ((TextView) row.findViewById(101)).setText(info.label);
            CheckBox cb = (CheckBox) row.findViewById(102);
            cb.setChecked(selected.contains(info.pkg));
            // В режиме «VPN для всего телефона» список некликабельный.
            cb.setEnabled(!config.getVpnAllApps());
            cb.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (selected.contains(info.pkg)) {
                        selected.remove(info.pkg);
                    } else {
                        selected.add(info.pkg);
                    }
                    config.setAllowedApps(selected);
                    GrizzlyLandVpnService.requestApply(AppSelectionActivity.this);
                }
            });

            return row;
        }
    }
}
