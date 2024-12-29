# Overall 
- The fastbin double-free check only ensures that a chunk being freed into a fastbin is not already the first chunk in that bin, if a different chunk of the same size is freed between the double-free then the check passes. 

- For example, request chunks A & B, both of which are the same size and qualify for the fastbins when freed, then free chunk A. If chunk A is freed again immediately, the fastbin double-free check will fail because chunk A is already the first chunk in that fastbin. Instead, free chunk B, then free chunk A again. This way chunk B is the first chunk in that fastbin when chunk A is freed for the second time. Now request three chunks of the same size as A & B, malloc will return chunk A, then chunk B, then chunk A again. 

- This may yield an opportunity to read from or write to a chunk that is allocated for another purpose. Alternatively, it could be used to tamper with fastbin metadata, specifically the forward pointer (fd) of the double-freed chunk. This may allow a fake chunk to be linked into the fastbin which can be allocated, then used to read from or write to an arbitrary location. Fake chunks allocated in this way must pass a size field check which ensures their size field value matches the chunk size of the fastbin they are being allocated from. 
- Watch out for incompatible flags in fake size fields, a set NON_MAIN_ARENA flag with a clear CHUNK_IS_MMAPPED flag can cause a segfault as malloc attempts to locate a non-existent arena. 


# Approach

Leverage a ***double-free bug*** to coerce malloc into ***returning the same chunk twice***, without freeing it in between. This technique is typically capitalised upon by corrupting fastbin metadata to ***link a fake chunk into a fastbin***. This fake chunk can be allocated, then program functionality could be used to ***read from or write to an arbitrary memory location.***
# Further use 

***The malloc hook*** is a good target for this technique, the 3 most-significant bytes of the _IO_wide_data_0 vtable pointer can be used in conjunction with part of the succeeding padding quadword to form a **reliable 0x7f size field.** 
- **This works because allocations are subject neither to alignment checks nor to flag corruption checks.**  
- 
# Limitations 
***The fastbin size field check*** during allocation limits candidates for fake chunks. 

