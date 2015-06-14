use known_nodes::KnownNode;

pub trait Persister {
    fn get_known_nodes(&self) -> &Vec<KnownNode>;
    fn add_known_node(&mut self, known_node: KnownNode);
}

pub struct MemoryPersister {
    known_nodes: Vec<KnownNode>
}

impl MemoryPersister {
    pub fn new() -> MemoryPersister {
        MemoryPersister {
            known_nodes: vec![]
        }
    }
}

impl Persister for MemoryPersister {
    fn get_known_nodes(&self) -> &Vec<KnownNode> {
        &self.known_nodes
    }

    fn add_known_node(&mut self, known_node: KnownNode) {
        self.known_nodes.push(known_node);
    }
}
