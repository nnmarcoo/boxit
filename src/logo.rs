use eframe::egui::{Color32, Pos2, Shape, Stroke, Ui};

pub fn draw_logo(tl: Pos2, ui: &Ui, scale: f32, offset: Pos2) {
    let painter = ui.painter();
    let color = Color32::from_gray(193);
    let stroke = Stroke::NONE;

    painter.add(Shape::convex_polygon(
        vec![
            Pos2::new(
                offset.x + tl.x + 0.16447368 * scale,
                offset.y + tl.y + 0.05275229 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.52412281 * scale,
                offset.y + tl.y + 0.38073394 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.25877193 * scale,
                offset.y + tl.y + 0.95183486 * scale,
            ),
            Pos2::new(offset.x + tl.x, offset.y + tl.y + 0.55963303 * scale),
        ],
        color,
        stroke,
    ));

    painter.add(Shape::convex_polygon(
        vec![
            Pos2::new(
                offset.x + tl.x + 0.25438596 * scale,
                offset.y + tl.y + 0.00229358 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.62280702 * scale,
                offset.y + tl.y + 0.10550459 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.97807018 * scale,
                offset.y + tl.y + 0.35091743 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.625 * scale,
                offset.y + tl.y + 0.30504587 * scale,
            ),
        ],
        color,
        stroke,
    ));

    painter.add(Shape::convex_polygon(
        vec![
            Pos2::new(
                offset.x + tl.x + 0.64035088 * scale,
                offset.y + tl.y + 0.43348624 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.99561404 * scale,
                offset.y + tl.y + 0.44724771 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.73464912 * scale,
                offset.y + tl.y + 0.87844037 * scale,
            ),
            Pos2::new(
                offset.x + tl.x + 0.35745614 * scale,
                offset.y + tl.y + 0.99541284 * scale,
            ),
        ],
        color,
        stroke,
    ));
}
