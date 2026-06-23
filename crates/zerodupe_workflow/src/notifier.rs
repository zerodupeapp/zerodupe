pub trait StateChangeNotifier: Send + Sync {
    fn notify_state_changed(&self, from: &str, to: &str);
}
