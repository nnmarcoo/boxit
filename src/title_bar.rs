use crate::logo::draw_logo;
use crate::Boxit;
use eframe::egui::{
    menu, vec2, Align, Button, Context, Layout, PointerButton, Pos2, RichText, Sense,
    TopBottomPanel, ViewportCommand,
};

pub fn render_title_bar(app: &Boxit, ctx: &Context) {
    TopBottomPanel::top("title_bar").show(ctx, |ui| {
        let response = ui.interact(ui.max_rect(), ui.id(), Sense::click_and_drag());

        if response.drag_started_by(PointerButton::Primary) {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }

        if response.double_clicked_by(PointerButton::Primary) {
            let is_maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::Maximized(!is_maximized));
        }

        ui.add_space(4.);
        menu::bar(ui, |ui| {
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let res = ui
                    .add(Button::new("").min_size(vec2(25., 25.)).rounding(3.))
                    .on_hover_text("v0.1.0");
                draw_logo(res.rect.left_top(), ui, 20., Pos2::new(2.5, 2.5));

                if res.clicked() {
                    webbrowser::open("https://github.com/nnmarcoo/boxit").unwrap();
                }
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        !app.busy,
                        Button::new(RichText::new("\u{1F5D9}").size(20.)).rounding(3.),
                    )
                    .on_hover_text("Close")
                    .clicked()
                {
                    ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                }

                if ui
                    .add(Button::new(RichText::new("\u{1F5D6}").size(20.)).rounding(3.))
                    .on_hover_text(if ui.input(|i| i.viewport().maximized.unwrap_or(false)) {
                        "Restore"
                    } else {
                        "Maximize"
                    })
                    .clicked()
                {
                    let is_maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
                    ui.ctx()
                        .send_viewport_cmd(ViewportCommand::Maximized(!is_maximized));
                }

                if ui
                    .add(Button::new(RichText::new("\u{1F5D5}").size(20.)).rounding(3.))
                    .on_hover_text("Minimize")
                    .clicked()
                {
                    ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true));
                }
            });
        });
        ui.add_space(2.);
    });
}
