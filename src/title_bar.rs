use crate::Boxit;
use eframe::egui::{
    menu, Align, Button, Context, ImageButton, Layout, PointerButton, RichText, Sense,
    TopBottomPanel, ViewportCommand,
};

pub fn render_title_bar(app: &Boxit, ctx: &Context) {
    TopBottomPanel::top("title_bar").show(ctx, |ui| {
        if ui
            .interact(ui.max_rect(), ui.id(), Sense::click_and_drag())
            .drag_started_by(PointerButton::Primary)
        {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }

        ui.add_space(4.);
        menu::bar(ui, |ui| {
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                if let Some(texture) = &app.texture {
                    if ui
                        .add(ImageButton::new(texture).rounding(3.))
                        .on_hover_text("v0.1.0")
                        .clicked()
                    {
                        webbrowser::open("https://github.com/nnmarcoo/boxit").unwrap();
                    }
                }
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(!app.busy, Button::new(RichText::new("\u{1F5D9}").size(20.)).rounding(3.))
                    .on_hover_text("Close")
                    .clicked()
                {
                    ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                }

                ui.add_space(-4.);

                if ui.input(|i| i.viewport().maximized.unwrap_or(false)) {
                    if ui
                        .add(Button::new(RichText::new("\u{1F5D6}").size(20.)).rounding(3.))
                        .on_hover_text("Restore window")
                        .clicked()
                    {
                        ui.ctx()
                            .send_viewport_cmd(ViewportCommand::Maximized(false));
                    }
                } else {
                    if ui
                        .add(Button::new(RichText::new("\u{1F5D6}").size(20.)).rounding(3.))
                        .on_hover_text("Maximize window")
                        .clicked()
                    {
                        ui.ctx().send_viewport_cmd(ViewportCommand::Maximized(true));
                    }
                }

                ui.add_space(-4.);

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
