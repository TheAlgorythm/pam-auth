use std::path::PathBuf;

pub struct PathComponent {
    path: PathBuf,
}

impl PathComponent {
    pub fn new<S: Into<PathBuf>>(component: S) -> Option<Self> {
        let component = Self {
            path: component.into(),
        };

        component.is_valid().then_some(component)
    }

    fn is_valid(&self) -> bool {
        use std::path::Component;

        let mut components = self.path.components();
        matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        )
    }
}

impl AsRef<std::path::Path> for PathComponent {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

pub trait PushPathComponent {
    fn push_component(&mut self, component: PathComponent);
}

impl PushPathComponent for PathBuf {
    fn push_component(&mut self, component: PathComponent) {
        self.push(component);
    }
}
