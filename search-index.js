var searchIndex = JSON.parse('{\
"rsdiff":{"doc":"rsdiff(1).A simple implementation of `rdiff(1)`.","i":[[3,"Delta","rsdiff","Delta between two buffers, this dose not require the…",null,null],[3,"IndexedSignature","","A Small representation of the orignal [`Signature`]. this…",null,null],[3,"RollingHasher","","An Adler-32 checksum modification with rolling operation.…",null,null],[3,"Signature","","A Buffer Signature.",null,null],[4,"Operation","","Operation to be done to upgrade from original version of…",null,null],[13,"Insert","","Insertation Operation to be performed by inserting the…",0,null],[12,"buffer","rsdiff::Operation","",1,null],[12,"offset","","",1,null],[13,"Remove","rsdiff","Removeal Operation to be performed by removing the `len`…",0,null],[12,"offset","rsdiff::Operation","",2,null],[12,"len","","",2,null],[5,"diff","rsdiff","Convenience function to compute [`Delta`] between two…",null,[[],[["operation",4],["vec",3]]]],[5,"diff_with_block_size","","Same as [`diff`]. but with more control over the…",null,[[],[["operation",4],["vec",3]]]],[11,"is_insert","","",0,[[]]],[11,"is_remove","","",0,[[]]],[11,"offset","","",0,[[]]],[11,"len","","",0,[[]]],[11,"is_empty","","",0,[[]]],[11,"buffer","","Current Operation buffer, returns [`None`] if the…",0,[[],["option",4]]],[11,"new","","Create new [`Delta`].",3,[[["indexedsignature",3]]]],[11,"operations","","Get the operations calculated so far.",3,[[]]],[11,"into_operations","","Consume `Self` and returns the operations to be then used…",3,[[],[["operation",4],["vec",3]]]],[11,"diff","","Calculate the diff between the original and modified…",3,[[],["result",6]]],[11,"new","","Create a new `RollingHasher`. Everything is zero at first…",4,[[]]],[11,"digest","","return the current checksum digest calculated so far.",4,[[]]],[11,"count","","returns how many bytes we rolled in so far.",4,[[]]],[11,"update","","Adds `bytes` to the checksum and update the internal…",4,[[]]],[11,"insert","","Rolling in a `byte`. Inserts the given `bytes` into the…",4,[[]]],[11,"remove","","Rolling out a `byte`. Removes the given `byte` that was…",4,[[]]],[11,"reset","","Reset hasher instance to its initial state.",4,[[]]],[11,"new","","Create a new Signature with dynamic `block_size` depends…",5,[[]]],[11,"with_block_size","","Create a new Signature with static `block_size`.",5,[[]]],[11,"block_size","","get the block size used by this signature.",5,[[]]],[11,"calculate","","Calculate the signature for the current buffer.",5,[[]]],[11,"to_indexed","","Convert the current Signature into the indexed one. this…",5,[[],["indexedsignature",3]]],[11,"from","","",3,[[]]],[11,"into","","",3,[[]]],[11,"to_owned","","",3,[[]]],[11,"clone_into","","",3,[[]]],[11,"borrow","","",3,[[]]],[11,"borrow_mut","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"from","","",6,[[]]],[11,"into","","",6,[[]]],[11,"to_owned","","",6,[[]]],[11,"clone_into","","",6,[[]]],[11,"borrow","","",6,[[]]],[11,"borrow_mut","","",6,[[]]],[11,"try_from","","",6,[[],["result",4]]],[11,"try_into","","",6,[[],["result",4]]],[11,"type_id","","",6,[[],["typeid",3]]],[11,"from","","",4,[[]]],[11,"into","","",4,[[]]],[11,"to_owned","","",4,[[]]],[11,"clone_into","","",4,[[]]],[11,"borrow","","",4,[[]]],[11,"borrow_mut","","",4,[[]]],[11,"try_from","","",4,[[],["result",4]]],[11,"try_into","","",4,[[],["result",4]]],[11,"type_id","","",4,[[],["typeid",3]]],[11,"from","","",5,[[]]],[11,"into","","",5,[[]]],[11,"to_owned","","",5,[[]]],[11,"clone_into","","",5,[[]]],[11,"borrow","","",5,[[]]],[11,"borrow_mut","","",5,[[]]],[11,"try_from","","",5,[[],["result",4]]],[11,"try_into","","",5,[[],["result",4]]],[11,"type_id","","",5,[[],["typeid",3]]],[11,"from","","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_owned","","",0,[[]]],[11,"clone_into","","",0,[[]]],[11,"to_string","","",0,[[],["string",3]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"clone","","",0,[[],["operation",4]]],[11,"clone","","",3,[[],["delta",3]]],[11,"clone","","",4,[[],["rollinghasher",3]]],[11,"clone","","",5,[[],["signature",3]]],[11,"clone","","",6,[[],["indexedsignature",3]]],[11,"default","","",4,[[]]],[11,"eq","","",0,[[["operation",4]]]],[11,"ne","","",0,[[["operation",4]]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",3,[[["formatter",3]],["result",6]]],[11,"fmt","","",4,[[["formatter",3]],["result",6]]],[11,"fmt","","",6,[[["formatter",3]],["result",6]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]]],"p":[[4,"Operation"],[13,"Insert"],[13,"Remove"],[3,"Delta"],[3,"RollingHasher"],[3,"Signature"],[3,"IndexedSignature"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);