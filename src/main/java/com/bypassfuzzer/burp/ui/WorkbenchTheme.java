package com.bypassfuzzer.burp.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.border.TitledBorder;
import javax.swing.plaf.basic.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ContainerAdapter;
import java.awt.event.ContainerEvent;

/** Component-local styling. Never changes Burp's LookAndFeel or UIManager defaults. */
public final class WorkbenchTheme {
    public static final Color SURFACE = new Color(0x202224);
    public static final Color EDITOR = new Color(0x191B1D);
    public static final Color CONTROL = new Color(0x2B2E31);
    public static final Color LINE = new Color(0x3B3E41);
    public static final Color TEXT = new Color(0xF0F1F2);
    public static final Color MUTED = new Color(0xB6BABE);
    public static final Color ACCENT = new Color(0xF28B50);
    public static final Color SELECTION = new Color(0x554032);
    public static final Color WARNING = new Color(0xF0BD68);
    public static final Color POSITIVE = new Color(0xA4D78D);
    public static final Font BODY = new Font(Font.SANS_SERIF, Font.PLAIN, 14);
    public static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final String STYLED = "bypassfuzzer.styled";
    private static final String NATIVE = "bypassfuzzer.nativeEditor";
    private static final String PRIMARY = "bypassfuzzer.primary";

    private WorkbenchTheme() { }

    /** Burp owns the editor internals, settings, syntax colors and accessibility. */
    public static Component nativeEditor(Component component) {
        if (component instanceof JComponent c) c.putClientProperty(NATIVE, true);
        return component;
    }

    public static JButton primary(JButton button) {
        button.putClientProperty(PRIMARY, true);
        return button;
    }

    public static JLabel title(String text) {
        JLabel label = new JLabel(text);
        label.setFont(BODY.deriveFont(Font.BOLD, 24f));
        label.putClientProperty("bypassfuzzer.heading", true);
        return label;
    }

    public static JLabel muted(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(MUTED);
        return label;
    }

    public static JPanel heading(String title, String description) {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(18, 20, 16, 20));
        panel.add(title(title), BorderLayout.NORTH);
        panel.add(muted(description), BorderLayout.CENTER);
        return panel;
    }

    public static Border sectionBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, LINE), title,
            TitledBorder.LEADING, TitledBorder.TOP, BODY.deriveFont(Font.BOLD), TEXT);
        return BorderFactory.createCompoundBorder(border,
            BorderFactory.createEmptyBorder(8, 8, 10, 8));
    }

    /** Idempotent, including components inserted after initial construction. */
    public static void apply(Component component) {
        if (!(component instanceof JComponent c)
            || Boolean.TRUE.equals(c.getClientProperty(NATIVE))) return;
        if (Boolean.TRUE.equals(c.getClientProperty(STYLED))) return;
        c.putClientProperty(STYLED, true);
        Color oldForeground = c.getForeground();
        c.setBackground(SURFACE);
        c.setForeground(TEXT);
        if (!Boolean.TRUE.equals(c.getClientProperty("bypassfuzzer.heading"))) c.setFont(BODY);
        if (oldForeground != null && !(oldForeground instanceof javax.swing.plaf.UIResource)) {
            if (oldForeground.equals(MUTED)) c.setForeground(MUTED);
            else if (oldForeground.getRed() > oldForeground.getGreen() + 50) c.setForeground(WARNING);
        }
        c.setBorder(themedBorder(c.getBorder()));
        c.putClientProperty(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        if (c instanceof JButton button) {
            button.setUI(new ButtonUI());
            button.setOpaque(false);
            button.setContentAreaFilled(false);
            button.setRolloverEnabled(true);
            boolean close = Boolean.TRUE.equals(button.getClientProperty("bypassfuzzer.close"));
            button.setBorder(close ? BorderFactory.createEmptyBorder(0, 0, 0, 0)
                : BorderFactory.createEmptyBorder(8, 13, 8, 13));
            button.setForeground(Boolean.TRUE.equals(button.getClientProperty(PRIMARY)) ? EDITOR : TEXT);
        } else if (c instanceof JCheckBox box) {
            box.setOpaque(false);
        } else if (c instanceof JTabbedPane tabs) {
            tabs.setUI(new TabsUI());
            tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        } else if (c instanceof JTable table) {
            table.setRowHeight(32);
            table.setShowVerticalLines(false);
            table.setShowHorizontalLines(true);
            table.setGridColor(LINE);
            table.setIntercellSpacing(new Dimension(0, 1));
            table.setSelectionBackground(SELECTION);
            table.setSelectionForeground(TEXT);
            table.setFillsViewportHeight(true);
            table.getTableHeader().setBackground(CONTROL);
            table.getTableHeader().setForeground(MUTED);
            table.getTableHeader().setFont(BODY.deriveFont(Font.BOLD, 13f));
            table.getTableHeader().setPreferredSize(new Dimension(0, 34));
            configureTableColumns(table);
            TableCellRenderer original = table.getTableHeader().getDefaultRenderer();
            table.getTableHeader().setDefaultRenderer((owner, value, selected, focused, row, column) -> {
                Component rendered = original.getTableCellRendererComponent(owner, value, selected, focused, row, column);
                rendered.setBackground(SURFACE);
                rendered.setForeground(MUTED);
                rendered.setFont(BODY.deriveFont(Font.BOLD, 13f));
                if (rendered instanceof JLabel label) {
                    label.setHorizontalAlignment(columnAlignment(owner.getColumnName(column)));
                    label.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 1, 0, LINE),
                        BorderFactory.createEmptyBorder(0, 8, 0, 8)));
                }
                return rendered;
            });
        } else if (c instanceof JTextComponent text) {
            text.setBackground(EDITOR);
            text.setCaretColor(TEXT);
            text.setSelectionColor(SELECTION);
            text.setSelectedTextColor(TEXT);
            text.setDisabledTextColor(MUTED);
            if (text instanceof JTextArea || text instanceof JEditorPane) text.setFont(MONO);
            if (!text.isOpaque()) {
                text.setFont(BODY);
                text.setForeground(MUTED);
                text.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
            } else {
                text.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(LINE), BorderFactory.createEmptyBorder(6, 8, 6, 8)));
            }
        } else if (c instanceof JComboBox<?> combo) {
            combo.setUI(new ComboUI());
            combo.setBackground(CONTROL);
        } else if (c instanceof JScrollPane scroll) {
            if (!(scroll.getBorder() instanceof javax.swing.border.CompoundBorder))
                scroll.setBorder(BorderFactory.createEmptyBorder());
            scroll.getViewport().setBackground(EDITOR);
        } else if (c instanceof JScrollBar bar) {
            bar.setUI(new ScrollUI());
            bar.setPreferredSize(new Dimension(10, 10));
        } else if (c instanceof JSplitPane split) {
            split.setUI(new BasicSplitPaneUI());
            split.setBorder(BorderFactory.createEmptyBorder());
            split.setDividerSize(6);
            split.setContinuousLayout(true);
            split.setOneTouchExpandable(false);
            if (split.getUI() instanceof BasicSplitPaneUI ui) {
                ui.getDivider().setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, LINE));
                ui.getDivider().setBackground(SURFACE);
            }
        } else if (c instanceof JSlider slider) {
            slider.setOpaque(false);
        }

        // Popups and editor internals are intentionally outside this traversal.
        for (Component child : c.getComponents()) apply(child);
        c.addContainerListener(new ContainerAdapter() {
            @Override public void componentAdded(ContainerEvent event) { apply(event.getChild()); }
        });
    }

    /** Keep short metadata aligned with its header and leave spare width for request details. */
    private static void configureTableColumns(JTable table) {
        for (int viewColumn = 0; viewColumn < table.getColumnCount(); viewColumn++) {
            TableColumn column = table.getColumnModel().getColumn(viewColumn);
            String name = table.getColumnName(viewColumn);
            switch (name) {
                case "#" -> columnWidth(column, 44, 48, 60);
                case "Status" -> columnWidth(column, 112, 128, 144);
                case "Length" -> columnWidth(column, 80, 96, 112);
                case "Run" -> columnWidth(column, 44, 52, 60);
                case "Method" -> columnWidth(column, 72, 84, 100);
                case "Group" -> columnWidth(column, 96, 104, 120);
                case "Mode" -> columnWidth(column, 128, 136, 152);
                case "State" -> columnWidth(column, 108, 140, 180);
                case "Sent" -> columnWidth(column, 64, 80, 100);
                case "Open", "Stop" -> columnWidth(column, 80, 88, 104);
                case "Pause / Resume" -> columnWidth(column, 156, 164, 180);
                default -> { }
            }
            TableCellRenderer original = column.getCellRenderer();
            if (original == null) original = table.getDefaultRenderer(table.getColumnClass(viewColumn));
            TableCellRenderer delegate = original;
            column.setCellRenderer((owner, value, selected, focused, row, viewIndex) -> {
                Component rendered = delegate.getTableCellRendererComponent(owner, value, selected, focused, row, viewIndex);
                // Renderers reuse labels, so reset text columns as well as centering metadata.
                if (rendered instanceof JLabel label)
                    label.setHorizontalAlignment(columnAlignment(owner.getColumnName(viewIndex)));
                return rendered;
            });
        }
    }

    private static int columnAlignment(String name) {
        return switch (name) {
            case "#", "Status", "Length", "Run", "Method", "Group", "Mode", "State",
                 "Progress", "Sent", "Open", "Pause / Resume", "Stop" -> SwingConstants.CENTER;
            default -> SwingConstants.LEFT;
        };
    }

    private static void columnWidth(TableColumn column, int minimum, int preferred, int maximum) {
        column.setMaxWidth(maximum);
        column.setMinWidth(minimum);
        column.setPreferredWidth(preferred);
        column.setWidth(preferred);
    }

    private static Border themedBorder(Border border) {
        if (border instanceof TitledBorder titled) return sectionBorder(titled.getTitle());
        if (border instanceof CompoundBorder compound) return BorderFactory.createCompoundBorder(
            themedBorder(compound.getOutsideBorder()), themedBorder(compound.getInsideBorder()));
        return border;
    }

    private static final class ButtonUI extends BasicButtonUI {
        @Override public void update(Graphics graphics, JComponent component) {
            AbstractButton button = (AbstractButton) component;
            boolean primary = Boolean.TRUE.equals(button.getClientProperty(PRIMARY));
            Color fill = primary ? ACCENT : CONTROL;
            if (!button.isEnabled()) fill = SURFACE;
            else if (button.getModel().isPressed()) fill = primary ? ACCENT.darker() : SELECTION;
            else if (button.getModel().isRollover()) fill = primary ? ACCENT.brighter() : LINE;
            Graphics2D g = (Graphics2D) graphics.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(fill);
            g.fillRoundRect(0, 0, component.getWidth() - 1, component.getHeight() - 1, 6, 6);
            g.setColor(button.hasFocus() ? ACCENT : LINE);
            g.drawRoundRect(0, 0, component.getWidth() - 1, component.getHeight() - 1, 6, 6);
            g.dispose();
            paint(graphics, component);
        }

        @Override protected void paintText(Graphics g, AbstractButton button, Rectangle rect, String text) {
            g.setColor(button.isEnabled() ? button.getForeground() : MUTED.darker());
            javax.swing.plaf.basic.BasicGraphicsUtils.drawStringUnderlineCharAt(
                g, text, button.getDisplayedMnemonicIndex(), rect.x,
                rect.y + g.getFontMetrics().getAscent());
        }
    }

    private static final class TabsUI extends BasicTabbedPaneUI {
        @Override protected void installDefaults() {
            super.installDefaults();
            tabInsets = new Insets(12, 18, 12, 18);
            selectedTabPadInsets = new Insets(0, 0, 0, 0);
            tabAreaInsets = new Insets(0, 0, 0, 0);
            contentBorderInsets = new Insets(1, 0, 0, 0);
        }
        @Override protected void paintTabBackground(Graphics g, int placement, int index,
                int x, int y, int width, int height, boolean selected) {
            g.setColor(SURFACE);
            g.fillRect(x, y, width, height);
        }
        @Override protected void paintTabBorder(Graphics g, int placement, int index,
                int x, int y, int width, int height, boolean selected) {
            g.setColor(selected ? ACCENT : LINE);
            g.fillRect(x, y + height - (selected ? 3 : 1), width, selected ? 3 : 1);
        }
        @Override protected void paintFocusIndicator(Graphics g, int placement, Rectangle[] rectangles,
                int index, Rectangle icon, Rectangle text, boolean selected) {
            if (tabPane.hasFocus() && selected) {
                g.setColor(ACCENT);
                g.drawRect(text.x - 4, text.y - 3, text.width + 8, text.height + 6);
            }
        }
        @Override protected void paintContentBorder(Graphics g, int placement, int index) { }
    }

    private static final class ComboUI extends BasicComboBoxUI {
        @Override protected JButton createArrowButton() {
            return new BasicArrowButton(SwingConstants.SOUTH, CONTROL, CONTROL, MUTED, LINE);
        }
        @Override protected ListCellRenderer<Object> createRenderer() {
            return new DefaultListCellRenderer() {
                @Override public Component getListCellRendererComponent(JList<?> list, Object value,
                        int index, boolean selected, boolean focus) {
                    super.getListCellRendererComponent(list, value, index, selected, focus);
                    setBackground(selected ? SELECTION : CONTROL);
                    setForeground(TEXT);
                    setFont(BODY);
                    setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
                    return this;
                }
            };
        }
        @Override public void paintCurrentValueBackground(Graphics g, Rectangle bounds, boolean focus) {
            g.setColor(CONTROL);
            g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);
        }
    }

    private static final class ScrollUI extends BasicScrollBarUI {
        @Override protected void configureScrollBarColors() {
            thumbColor = LINE;
            thumbDarkShadowColor = LINE;
            thumbHighlightColor = LINE;
            thumbLightShadowColor = LINE;
            trackColor = SURFACE;
        }
        @Override protected JButton createDecreaseButton(int orientation) { return arrow(orientation); }
        @Override protected JButton createIncreaseButton(int orientation) { return arrow(orientation); }
        private JButton arrow(int orientation) {
            JButton button = new BasicArrowButton(orientation);
            button.setPreferredSize(new Dimension(0, 0));
            return button;
        }
    }
}
