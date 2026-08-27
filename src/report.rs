use anyhow::Result;
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook};
use std::path::Path;

use crate::checker::{CheckResult, CheckStatus};

pub fn write_xlsx_report(path: &Path, results: &[CheckResult]) -> Result<()> {
    let mut workbook = Workbook::new();

    let title = Format::new()
        .set_bold()
        .set_font_size(16)
        .set_font_color(Color::White)
        .set_background_color(Color::RGB(0x17365D));

    let header = Format::new()
        .set_bold()
        .set_font_color(Color::White)
        .set_background_color(Color::RGB(0x1F4E78))
        .set_border(FormatBorder::Thin)
        .set_align(FormatAlign::Center);

    let normal = Format::new().set_border(FormatBorder::Thin);

    let listed = Format::new()
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xFFC7CE))
        .set_font_color(Color::RGB(0x9C0006));

    let clean = Format::new()
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xC6EFCE))
        .set_font_color(Color::RGB(0x006100));

    let error = Format::new()
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xFFEB9C))
        .set_font_color(Color::RGB(0x9C6500));

    {
        let ws = workbook.add_worksheet();
        ws.set_name("DBL Results")?;
        ws.merge_range(0, 0, 0, 5, "Spamhaus DBL Domain Reputation Report", &title)?;
        ws.set_row_height(0, 26)?;

        let headers = ["Domain", "Status", "Category", "Return Code(s)", "DNS Query", "Detail"];
        for (col, value) in headers.iter().enumerate() {
            ws.write_string_with_format(2, col as u16, *value, &header)?;
        }

        for (index, result) in results.iter().enumerate() {
            let row = (index + 3) as u32;
            let row_format = match result.status {
                CheckStatus::Listed => &listed,
                CheckStatus::NotListed => &clean,
                CheckStatus::Error => &error,
            };

            let codes = if result.return_codes.is_empty() {
                "-".to_string()
            } else {
                result.return_codes.join("; ")
            };

            ws.write_string_with_format(row, 0, &result.domain, row_format)?;
            ws.write_string_with_format(row, 1, result.status_label(), row_format)?;
            ws.write_string_with_format(row, 2, result.category_text(), row_format)?;
            ws.write_string_with_format(row, 3, &codes, row_format)?;
            ws.write_string_with_format(row, 4, &result.query, &normal)?;
            ws.write_string_with_format(row, 5, &result.detail, &normal)?;
        }

        let last_row = (results.len() + 2) as u32;
        ws.autofilter(2, 0, last_row, 5)?;
        ws.set_freeze_panes(3, 0)?;
        ws.set_column_width(0, 32)?;
        ws.set_column_width(1, 14)?;
        ws.set_column_width(2, 38)?;
        ws.set_column_width(3, 23)?;
        ws.set_column_width(4, 58)?;
        ws.set_column_width(5, 72)?;
    }

    {
        let ws = workbook.add_worksheet();
        ws.set_name("Summary")?;
        ws.merge_range(0, 0, 0, 3, "Scan Summary", &title)?;

        let listed_count = results.iter().filter(|r| r.is_listed()).count() as f64;
        let clean_count = results.iter().filter(|r| r.is_not_listed()).count() as f64;
        let error_count = results.len() as f64 - listed_count - clean_count;

        ws.write_string_with_format(2, 0, "Metric", &header)?;
        ws.write_string_with_format(2, 1, "Count", &header)?;
        ws.write_string_with_format(3, 0, "Domains checked", &normal)?;
        ws.write_number_with_format(3, 1, results.len() as f64, &normal)?;
        ws.write_string_with_format(4, 0, "LISTED", &listed)?;
        ws.write_number_with_format(4, 1, listed_count, &listed)?;
        ws.write_string_with_format(5, 0, "NOT LISTED", &clean)?;
        ws.write_number_with_format(5, 1, clean_count, &clean)?;
        ws.write_string_with_format(6, 0, "ERROR", &error)?;
        ws.write_number_with_format(6, 1, error_count, &error)?;

        ws.write_string_with_format(8, 0, "Interpretation", &header)?;
        ws.write_string_with_format(9, 0, "Red", &listed)?;
        ws.write_string_with_format(9, 1, "Spamhaus DBL returned a malicious/abuse listing code.", &normal)?;
        ws.write_string_with_format(10, 0, "Green", &clean)?;
        ws.write_string_with_format(10, 1, "No DBL A record returned (NXDOMAIN/no records).", &normal)?;
        ws.write_string_with_format(11, 0, "Yellow", &error)?;
        ws.write_string_with_format(11, 1, "Resolver, query-limit, public-resolver or unexpected response. Do not classify as malicious.", &normal)?;

        ws.set_column_width(0, 24)?;
        ws.set_column_width(1, 78)?;
    }

    workbook.save(path)?;
    Ok(())
}
