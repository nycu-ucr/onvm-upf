#ifdef DMALLOC
#include <dmalloc.h>
#endif
#ifndef  RBTREE_H
#define  RBTREE_H
#include <functional>
#include "Common.h"
#include"misc.h"
#include"stack.h"
#include "../ElementaryClasses.h"
#include <vector>
#include <stack>
#include <algorithm>
#include <cstdint>
/*  CONVENTIONS:  All data structures for red-black trees have the prefix */
/*                "rb_" to prevent name conflicts. */
/*                                                                      */
/*                Function names: Each word in a function name begins with */
/*                a capital letter.  An example funcntion name is  */
/*                CreateRedTree(a,b,c). Furthermore, each function name */
/*                should begin with a capital letter to easily distinguish */
/*                them from variables. */
/*                                                                     */
/*                Variable names: Each word in a variable name begins with */
/*                a capital letter EXCEPT the first letter of the variable */
/*                name.  For example, int newLongInt.  Global variables have */
/*                names beginning with "g".  An example of a global */
/*                variable name is gNewtonsConstant. */

/* comment out the line below to remove all the debugging assertion */
/* checks from the compiled code.  */


static const int LOW = 0, HIGH = 1;
struct rb_red_blk_tree;
typedef std::array<Point, 2>  box; 

//Total 29 bytes per node
typedef struct rb_red_blk_node {
	box key;
	rb_red_blk_node* left;
	rb_red_blk_node* right;
	rb_red_blk_tree * rb_tree_next_level;
	//int priority; /*max_priority of all children*/
	bool red; /* if red=0 then the node is black */
	rb_red_blk_node* parent;

} rb_red_blk_node; 


//Total 
// typedef struct rb_red_blk_tree { 
//   /*  A sentinel is used for root and for nil.  These sentinels are */
//   /*  created when RBTreeCreate is caled.  root->left should always */
//   /*  point to the node which is the root of the tree.  nil points to a */
//   /*  node which should always be black but has aribtrary children and */
//   /*  parent and no key or info.  The point of using these sentinels is so */
//   /*  that the root and nil nodes do not require special cases in the code */
//   rb_red_blk_node* root;             
//   rb_red_blk_node* nil;   
   
//   int count = 0;
//   std::vector<box> chain_boxes;
//   //std::priority_queue<int> pq;
//   std::vector<int> priority_list;
//   int max_priority_local = -1;

//   void PrintKey(const box& b)
//   {
// 	  printf("[%u %u]\n", b[LowDim], b[HighDim]);
//   }
//   void PushPriority(int p) {
 
// 	  max_priority_local = std::max(p, max_priority_local);
// 	  priority_list.push_back(p);
//   }
//   void PopPriority(int p) {
// 	  auto result = find(begin(priority_list), end(priority_list),p);
// 	  priority_list.erase(find(begin(priority_list), end(priority_list), p));
// 	  if (p == max_priority_local ) {
// 		  max_priority_local = *std::max_element(begin(priority_list), end(priority_list));
// 	  }
// 	  if (priority_list.empty()) max_priority_local = -1;
//   }
//   void ClearPriority() {
// 	  max_priority_local = -1;
// 	  priority_list.clear();
//   }
//   int GetMaxPriority() const {
// 	  return max_priority_local;
//   }
//   int GetSizeList() const{
// 	  return priority_list.size();
//   }
// } rb_red_blk_tree;


// typedef struct rb_red_blk_tree {
//     /* ------------ sentinel pointers ------------ */
//     rb_red_blk_node* root;   /* root->left is real root */
//     rb_red_blk_node* nil;    /* shared nil / leaf node  */

//     /* ------------ per-tree bookkeeping ---------- */
//     int count = 0;                       /* # rules in this tree            */
//     std::vector<box> chain_boxes;        /* bounding boxes for singleton    */

//     /* Parallel vectors: priority ↔︎ descriptor keep same indices */
//     std::vector<int>       priority_list;
//     std::vector<uintptr_t> descriptor_list;

//     /* Cached maxima for O(1) lookup */
//     int        max_priority_local   = -1;
//     uintptr_t  max_descriptor_local = 0;

//     /* ------------ debug helper ------------------ */
//     void PrintKey(const box& b) {
//         printf("[%u %u]\n", b[LowDim], b[HighDim]);
//     }

//     /* ------------ list maintenance -------------- */
//     void PushMatch(int p, uintptr_t d) {
//         priority_list  .push_back(p);
//         descriptor_list.push_back(d);
//         if (p > max_priority_local) {
//             max_priority_local   = p;
//             max_descriptor_local = d;
//         }
//     }

//     void PopMatch(int p, uintptr_t d) {
//         for (size_t i = 0; i < priority_list.size(); ++i) {
//             if (priority_list[i] == p && descriptor_list[i] == d) {
//                 priority_list  .erase(priority_list.begin()  + i);
//                 descriptor_list.erase(descriptor_list.begin() + i);
//                 break;
//             }
//         }
//         /* recompute cache */
//         max_priority_local   = -1;
//         max_descriptor_local = 0;
//         for (size_t i = 0; i < priority_list.size(); ++i) {
//             if (priority_list[i] > max_priority_local) {
//                 max_priority_local   = priority_list[i];
//                 max_descriptor_local = descriptor_list[i];
//             }
//         }
//     }

//     void ClearMatches() {
//         priority_list.clear();
//         descriptor_list.clear();
//         max_priority_local   = -1;
//         max_descriptor_local = 0;
//     }

//     /* ------------ getters ----------------------- */
//     int        GetMaxPriority()   const { return max_priority_local; }
//     uintptr_t  GetMaxDescriptor() const { return max_descriptor_local; }

//     MatchResult GetMaxMatch() const {
//         return { max_priority_local, max_descriptor_local };
//     }

//     int GetSizeList() const { return static_cast<int>(priority_list.size()); }

// } rb_red_blk_tree;

// typedef struct rb_red_blk_tree {
//     /* ------------ sentinel pointers ------------ */
//     rb_red_blk_node* root;   // root->left is the real root
//     rb_red_blk_node* nil;    // shared nil / leaf node

//     /* ------------ per‐tree bookkeeping ---------- */
//     int count = 0;                       // # rules in this tree
//     std::vector<box> chain_boxes;        // bounding boxes for singletons

//     /* ------------ match‐tracking -------------- */
//     // _one_ vector of (priority, descriptor) pairs
//     std::vector<MatchResult> matches;

//     /* Cached best match for O(1) lookup */
//     MatchResult best_match{ -1, 0 };

//     /* ------------ debug helper ------------------ */
//     void PrintKey(const box& b) const {
//         printf("[%u %u]\n", b[LowDim], b[HighDim]);
//     }

//     /* ------------ list maintenance -------------- */
//     void PushMatch(int p, uintptr_t d) {
//         matches.push_back({p, d});
//         if (p > best_match.priority) {
//             best_match = { p, d };
//         }
//     }

//     void PopMatch(int p, uintptr_t d) {
//         // find and erase the one matching pair
//         auto it = std::find_if(matches.begin(), matches.end(),
//             [&](auto &m){ return m.priority == p && m.descriptor == d; });
//         if (it != matches.end()) {
//             matches.erase(it);
//         }
//         // recompute best_match
//         best_match = { -1, 0 };
//         for (auto &m : matches) {
//             if (m.priority > best_match.priority) {
//                 best_match = m;
//             }
//         }
//     }

//     void ClearMatches() {
//         matches.clear();
//         best_match = { -1, 0 };
//     }

//     /* ------------ getters ----------------------- */
//     int        GetMaxPriority()   const { return best_match.priority; }
//     uintptr_t  GetMaxDescriptor() const { return best_match.descriptor; }
//     MatchResult GetMaxMatch()     const { return best_match; }
//     int        GetSizeList()      const { return static_cast<int>(matches.size()); }

// } rb_red_blk_tree;



// red_black_tree.h

typedef struct rb_red_blk_tree {
    /* ------------ sentinel pointers ------------ */
    rb_red_blk_node* root;   // root->left is the real root
    rb_red_blk_node* nil;    // shared nil / leaf node

    /* ------------ per‐tree bookkeeping ---------- */
    int                   count = 0;            // # rules in this tree
    std::vector<box>      chain_boxes;         // bounding boxes for singletons

    /* Parallel vectors: priority ↔ descriptor keep same indices */
    std::vector<int>       priority_list;
    std::vector<uintptr_t> descriptor_list;

    /* Cached maxima for O(1) lookup */
    int       max_priority_local   = -1;
    uintptr_t max_descriptor_local = 0;

    // --------------------------------------------------------------------
    // Constructor: reserve a small amount to avoid repeated reallocations
    rb_red_blk_tree()
      : root(nullptr),
        nil(nullptr),
        count(0),
        chain_boxes(),
        priority_list(),
        descriptor_list(),
        max_priority_local(-1),
        max_descriptor_local(0)
    {
        // Optimization Scope: Reserve for the *number of concurrent matches*
        //priority_list.  reserve(22);
        //descriptor_list.reserve(22);
    }
    // --------------------------------------------------------------------

    /* ------------ debug helper ------------------ */
    void PrintKey(const box& b) const {
        printf("[%u %u]\n", b[LowDim], b[HighDim]);
    }

    /* ------------ list maintenance -------------- */
    void PushMatch(int p, uintptr_t d) {

        //std::cout << "[PUSH] prio=" << p << " desc=0x" << std::hex << d << std::dec << '\n';

        priority_list.  push_back(p);
        descriptor_list.push_back(d);
        // update cache only if this is the new max
        if (p > max_priority_local) {
            max_priority_local   = p;
            max_descriptor_local = d;
        }
    }

    void PopMatch(int p, uintptr_t d) {
        const size_t n = priority_list.size();
        for (size_t i = 0; i < n; ++i) {
            if (priority_list[i] == p &&
                descriptor_list[i] == d)
            {
                // swap‐and‐pop both vectors in one go
                priority_list[i]   = priority_list[n-1];
                descriptor_list[i] = descriptor_list[n-1];
                priority_list.  pop_back();
                descriptor_list.pop_back();
                break;
            }
        }
        // recompute only once for the remaining entries
        max_priority_local   = -1;
        max_descriptor_local = 0;
        for (size_t i = 0, m = priority_list.size(); i < m; ++i) {
            int        pp = priority_list[i];
            uintptr_t  dd = descriptor_list[i];
            if (pp > max_priority_local) {
                max_priority_local   = pp;
                max_descriptor_local = dd;
            }
        }
    }

    void ClearMatches() {
        priority_list.  clear();
        descriptor_list.clear();
        max_priority_local   = -1;
        max_descriptor_local = 0;
    }

    /* ------------ getters ----------------------- */
    int        GetMaxPriority()   const { return max_priority_local;   }
    uintptr_t  GetMaxDescriptor() const { return max_descriptor_local; }
    MatchResult GetMaxMatch()     const {
        return { max_priority_local, max_descriptor_local };
    }
    int        GetSizeList()      const {
        return static_cast<int>(priority_list.size());
    }

} rb_red_blk_tree;




bool inline Overlap(unsigned int a1, unsigned  int a2, unsigned int b1, unsigned int b2) {
	if (a1 <= b1) {
		return((b1 <= a2));
	} else {
		return((a1 <= b2));
	}
}

/**
FOR RB tree light weight node
**/
rb_red_blk_tree* RBTreeCreate();

rb_red_blk_node * RBTreeInsertWithPathCompression(rb_red_blk_tree* tree, const std::vector<box>& key, unsigned int level, const FieldOrder& fieldOrder, int priority, uintptr_t descriptor=0);
void RBTreeDeleteWithPathCompression(rb_red_blk_tree*& tree, const std::vector<box>& key, int level, const FieldOrder& fieldOrder, int priority, uintptr_t descriptor, bool& JustDeletedTree);
std::vector<std::pair<rb_red_blk_tree*, rb_red_blk_node *>> RBFindNodeSequence(rb_red_blk_tree* tree, const std::vector<box>& key, int level, const FieldOrder& fieldOrder);

bool TreeInsertWithPathCompressionHelp(rb_red_blk_tree* tree, rb_red_blk_node* z, const std::vector<box>& b, int level, const FieldOrder& fieldOrder, int priority, uintptr_t descriptor, rb_red_blk_node*& out_ptr);
int RBExactQueryPriority(rb_red_blk_tree*  tree, const Packet& q, int level, const FieldOrder& fieldOrder, int priority_so_far); 
bool TreeInsertHelp(rb_red_blk_tree* tree, rb_red_blk_node* z, const std::vector<box>& b, int level, const FieldOrder& fieldOrder, int priority, uintptr_t descriptor, rb_red_blk_node*& out_ptr);
rb_red_blk_node * RBTreeInsert(rb_red_blk_tree* tree, const std::vector<box>& key, int level, const FieldOrder& fieldOrder, int priority=0, uintptr_t descriptor=0);
bool RBTreeCanInsert(rb_red_blk_tree* tree, const std::vector<box>& z, int level, const FieldOrder& fieldOrder);
void RBTreePrint(rb_red_blk_tree*);
void RBDelete(rb_red_blk_tree* , rb_red_blk_node* );
void RBTreeDestroy(rb_red_blk_tree*);
rb_red_blk_node* TreePredecessor(rb_red_blk_tree*,rb_red_blk_node*);
rb_red_blk_node* TreeSuccessor(rb_red_blk_tree*,rb_red_blk_node*);


void RBSerializeIntoRulesRecursion(rb_red_blk_tree * tree, rb_red_blk_node* node, int level, const FieldOrder& fieldOrder, std::vector<box>& boxes_so_far, std::vector<Rule>& rules_so_far);

std::vector<Rule> RBSerializeIntoRules(rb_red_blk_tree* tree, const FieldOrder& fieldOrder);

int RBExactQuery(rb_red_blk_tree* tree, const Packet& q, int level, const FieldOrder& fieldOrder);
stk_stack * RBEnumerate(rb_red_blk_tree* tree,void* low, void* high);
void NullFunction(void*);

int RBExactQueryIterative(rb_red_blk_tree*  tree, const Packet& q, const FieldOrder& fieldOrder);

MatchResult RBExactQueryIterativeMod(rb_red_blk_tree*  tree, const Packet& q, const FieldOrder& fieldOrder);

int  CalculateMemoryConsumptionRecursion(rb_red_blk_tree * treenode, rb_red_blk_node * node, int level, const FieldOrder& fieldOrder);
int CalculateMemoryConsumption(rb_red_blk_tree* tree, const FieldOrder& fieldOrder);

#endif