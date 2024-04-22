use std::fmt::Debug;

pub fn print_error<T: Debug>(
    f: &mut std::fmt::Formatter<'_>,
    desc: &'static str,
    err: T,
) -> std::fmt::Result {
    let mut res = Vec::<Result<(), std::fmt::Error>>::new();
    res.push(write!(f, "{}", desc));
    res.push(write!(f, "Error Information: {:?}", err));

    let has_error = res.iter().any(|r| r.is_err());
    if !has_error {
        return Ok(());
    }

    Err(res.iter().find(|r| r.is_err()).unwrap().unwrap_err())
}
