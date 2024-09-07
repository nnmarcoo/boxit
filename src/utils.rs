use eframe::egui::{ColorImage, Context, TextureHandle};
use image::load_from_memory;

pub fn load_embedded_image(ctx: &Context) -> TextureHandle {
    let image_data = include_bytes!("../assets/logo_gray_small.png");

    let img = load_from_memory(image_data).expect("Failed to load embedded image");
    let img = img.to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    let pixels = img.into_raw();

    let color_image = ColorImage::from_rgba_unmultiplied(size, &pixels);
    ctx.load_texture("embedded_image", color_image, Default::default())
}
